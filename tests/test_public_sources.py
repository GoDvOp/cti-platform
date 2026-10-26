import json
from pathlib import Path
import unittest
from app.collectors import parse_source, validate_sources
from app.extraction import extract
from app.models import Publication

class PublicSourceTests(unittest.TestCase):
    def source(self,kind,**kw):
        return dict(id='test',kind=kind,url='https://source.example/news/',allowed_hosts=['source.example'],
                    article_path=r'/news/[^/]+/?',program_path=r'/programs/[^/]+/?',platform='Test Bounty',**kw)

    def test_public_program_cards_do_not_gain_publication_date_from_observation(self):
        html=b'<html><article><a href="/programs/example/"><h3>Example Co</h3></a><p>Uses Product; rewards.</p><time datetime="2026-10-24T10:00:00Z"></time></article></html>'
        pubs,_=parse_source(html,self.source('bounty_listing'))
        self.assertEqual(len(pubs),1);self.assertIsNone(pubs[0].published_at)
        self.assertIsNone(pubs[0].metadata['publication_day'])
        result=extract(pubs[0],[{'id':'example','name':'Example Co'}],[{'id':'product','name':'Product'}])
        self.assertEqual(result['signals'],[]);self.assertEqual(result['assertions'],[])

    def test_foreign_program_links_are_not_collected(self):
        with self.assertRaises(ValueError):
            parse_source(b'<a href="https://other.example/programs/example">Example Co</a>',self.source('bounty_listing'))

    def test_empty_javascript_shell_is_reported_as_failure(self):
        with self.assertRaisesRegex(ValueError,'JavaScript'):
            parse_source(b'<html><div id="app"></div><script src="/bundle.js"></script></html>',self.source('publisher_news'))

    def test_structured_news_preserves_date_published_not_modified(self):
        ld={'@type':'NewsArticle','headline':'Example report','url':'/news/example/',
            'datePublished':'2026-10-01T12:00:00Z','dateModified':'2026-10-24T12:00:00Z'}
        pubs,_=parse_source(('<script type="application/ld+json">'+json.dumps(ld)+'</script>').encode(),self.source('publisher_news'))
        self.assertEqual(pubs[0].published_at,'2026-10-01T12:00:00+00:00')

    def test_trueconf_notice_requires_explicit_scope_and_keeps_version_limit(self):
        html=b'<article><h1>Security patch for TrueConf Server</h1><p>TrueConf Server: all versions up to and including 5.5.7. We recommend upgrading to TrueConf Server 5.5.8.</p><p>Date published: 22.10.2026</p></article>'
        s=self.source('vendor_notice',product_id='trueconf-server',product_name='TrueConf Server')
        pubs,_=parse_source(html,s)
        self.assertEqual(pubs[0].metadata['security_notice']['affected_ranges'],[{'lte':'5.5.7'}])
        self.assertEqual(pubs[0].metadata['publication_day'],'2026-10-22')
        self.assertEqual(extract(pubs[0],[])['cves'],[])
        with self.assertRaises(ValueError):
            parse_source(html.replace(b'all versions up to and including 5.5.7',b'some installations'),s)

    def test_program_page_does_not_collect_asset_scope(self):
        s=self.source('bounty_program',company_name='Example Co')
        html=b'<article><h1>Example Co</h1><p>Public research program for Example Co, not an attack.</p><h2>Scope</h2><p>private-assets.example</p></article>'
        pubs,_=parse_source(html,s)
        self.assertNotIn('private-assets',pubs[0].text)
        self.assertIsNone(pubs[0].published_at)

    def test_program_announcement_does_not_generate_attack_signal(self):
        pub=Publication('test','https://source.example/1','Example Co запускает программу Bug Bounty',
            'Компания Example Co запустила программу bug bounty. Исследователи могут искать уязвимости и SQL-инъекции.')
        result=extract(pub,[{'id':'example','name':'Example Co'}])
        self.assertEqual(result['event_type'],'bug_bounty_announcement');self.assertEqual(result['signals'],[])

    def test_real_configuration_is_valid_and_failed_sources_are_disabled(self):
        sources=json.loads((Path(__file__).resolve().parents[1]/'config/sources.json').read_text())
        validate_sources(sources)
        for sid in ('nckci_advisories','trueconf_case_roszarubezhneft'):
            self.assertFalse(next(s for s in sources if s['id']==sid)['enabled'])

    def test_structured_day_only_date_is_preserved_without_inventing_time(self):
        ld={'@type':'NewsArticle','headline':'Example report','url':'/news/example/','datePublished':'2026-10-01'}
        pubs,_=parse_source(('<script type="application/ld+json">'+json.dumps(ld)+'</script>').encode(),self.source('publisher_news'))
        self.assertIsNone(pubs[0].published_at)
        self.assertEqual(pubs[0].metadata['publication_day'],'2026-10-01')

    def test_standoff_program_name_does_not_include_reward_or_report_statistics(self):
        html=b'<a href="/programs/example"><div data-testid="programName">Example Co</div><p>Reward 400000, 42 valid reports</p></a>'
        pubs,_=parse_source(html,self.source('bounty_listing'))
        self.assertEqual(pubs[0].title,'Example Co');self.assertEqual(pubs[0].text,'Example Co')

    def test_secondary_read_link_does_not_replace_clean_news_headline(self):
        html='<article><a href="/news/example/">Example headline</a><a href="/news/example/">Читать – Example headline</a><time datetime="2026-10-24T10:00:00Z"></time></article>'
        pubs,_=parse_source(html.encode(),self.source('publisher_news'))
        self.assertEqual(len(pubs),1);self.assertEqual(pubs[0].title,'Example headline')

    def test_publisher_local_date_is_not_confused_with_utc_date(self):
        html=b'<meta property="article:published_time" content="2026-10-22T00:34:38+03:00"><article><h1>Example headline</h1><p>Meaningful public article text for testing.</p><p>Date published: 22.10.2026</p></article>'
        from app.public_sources import parse_article
        pubs,_=parse_article(html,self.source('publisher_news'))
        self.assertEqual(pubs[0].published_at,'2026-10-21T21:34:38+00:00')
