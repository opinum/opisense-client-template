import { Injectable, Inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import 'rxjs/add/operator/map';

@Injectable()
export class OpisenseService {
  constructor(
    private http: HttpClient,
    @Inject('BASE_URL') private baseUrl: string
  ) { }

  getSources() {
    const params: any = { 'paging.pageNumber': 0, 'paging.itemsPerPage': 20, displayLevel: 'verbose' };
    return this.http.get<OpisenseSource[]>(this.baseUrl + 'api/sources', { params: params });
  }

  getSourceVariables(source: OpisenseSource) {
    const params: any = { 'sourceId': source.id };
    return this.http.get<OpisenseVariable[]>(this.baseUrl + 'api/variables', { params: params });
  }

  getVariableData(variable: OpisenseVariable) {
    const params: any = {
      displayLevel: 'ValueVariableDate',
      'paging.pageNumber': 0,
      'paging.itemsPerPage': 5,
      variableId: variable.id,
      granularity: 'raw',
      pagingOrder: 'DESC'
    };
    return this.http.get<OpisenseData[]>(this.baseUrl + 'api/data', { params: params });
  }

}

export interface OpisenseData {
  date: Date;
  variableId: number;
  rawValue: number;
  unitId: number;
}

export interface OpisenseVariable {
  id: number;
  name: string;
  sourceId: number;
  variableTypeId: number;
  unitId: number;
  granularity: number;
  granularityTimeBase: string;
  quantityType: string;
  mappingConfig: string;
  aggregate: string;
}

export interface WeatherForecast {
  dateFormatted: string;
  temperatureC: number;
  temperatureF: number;
  summary: string;
}

export interface OpisenseUnit {
  divisor: number;
  id: number;
  name: string;
  offset: number;
  parentId: number;
  symbol: string;
  unitFamilyId: number;
}

export interface OpisenseSource {
  serialNumber: string;
  gatewayId: number;
  gatewayTypeId: number;
  meterNumber: string;
  localisation: string;
  description: string;
  tags: any[];
  id: number;
  energyTypeId: number;
  energyUsageId: number;
  name: string;
  sourceTypeId: number;
  timeZoneId: string;
  meterAddress: string;
  eanNumber: string;
}
