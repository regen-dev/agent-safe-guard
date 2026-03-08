#pragma once

#include "sg/rule_types.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace sg {

struct PackageCatalogEntry {
  std::string package;
  std::string version;
  std::string title;
  std::string summary;
  std::string category;
  std::string source_path;
  std::vector<RuleMetadata> rules;
};

struct InstalledPackageRecord {
  std::string package;
  std::string version;
  std::string source_path;
  std::string source_url;
  std::string catalog_id;
  std::string download_url;
  std::string sha256;
  std::string installed_path;
  long installed_at = 0;
};

struct CatalogSourceRecord {
  std::string catalog_id;
  std::string display_name;
  std::string source_url;
  std::string cache_path;
  long added_at = 0;
  long last_synced_at = 0;
};

struct CatalogPackageRecord {
  std::string catalog_id;
  std::string catalog_title;
  std::string catalog_source_url;
  std::string package;
  std::string version;
  std::string title;
  std::string summary;
  std::string download_url;
  std::string sha256;
  std::vector<std::string> tags;
  std::vector<std::string> phases;
  std::vector<RuleMetadata> rules;
};

std::filesystem::path DefaultInstalledPackagesDir();
std::filesystem::path DefaultInstalledStatePath();
std::filesystem::path DefaultCatalogsStatePath();
std::filesystem::path DefaultCatalogCacheDir();
std::string DefaultCatalogSourceUrl();
void EnsureCatalogStateScaffold();
std::vector<PackageCatalogEntry> LoadExternalPackageCatalog();
std::vector<InstalledPackageRecord> LoadInstalledPackageRecords();
std::vector<CatalogSourceRecord> LoadCatalogSourceRecords();
std::vector<CatalogPackageRecord> LoadCatalogPackageRecords();
bool AddCatalogSource(std::string_view source_url, std::string* error = nullptr);
bool SyncCatalogSources(std::string* error = nullptr);
bool InstallCatalogPackage(std::string_view selector,
                           std::string* error = nullptr);
bool InstallPackageManifestFile(const std::filesystem::path& source_path,
                                std::string* error = nullptr);
bool RemoveInstalledPackage(std::string_view package_name,
                            std::string* error = nullptr);

}  // namespace sg
