import { Controller, Get, Param, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CurrentUser } from '../auth/decorators/current-user.decorator';

type AuthUser = { id: string; email: string; name: string };

import { AiAnalysisService } from './ai-analysis.service';

@ApiTags('ai-analysis')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('ai-analysis')
export class AiAnalysisController {
  constructor(private readonly service: AiAnalysisService) {}

  @Get(':executionId')
  @ApiOperation({ summary: 'AI-powered vulnerability analysis for a scan execution' })
  analyze(@Param('executionId') executionId: string, @CurrentUser() user: AuthUser) {
    return this.service.analyzeExecution(executionId, user.id);
  }
}
