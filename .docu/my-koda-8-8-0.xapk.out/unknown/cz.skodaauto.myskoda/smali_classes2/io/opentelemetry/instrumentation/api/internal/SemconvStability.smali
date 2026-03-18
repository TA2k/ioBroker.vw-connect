.class public final Lio/opentelemetry/instrumentation/api/internal/SemconvStability;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final dbSystemNameMap:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private static final emitOldCodeSemconv:Z

.field private static final emitOldDatabaseSemconv:Z

.field private static final emitStableCodeSemconv:Z

.field private static final emitStableDatabaseSemconv:Z


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    const-string v0, "otel.semconv-stability.opt-in"

    .line 2
    .line 3
    invoke-static {v0}, Lio/opentelemetry/instrumentation/api/internal/ConfigPropertiesUtil;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/4 v1, 0x1

    .line 8
    if-eqz v0, :cond_2

    .line 9
    .line 10
    new-instance v2, Ljava/util/HashSet;

    .line 11
    .line 12
    const-string v3, ","

    .line 13
    .line 14
    invoke-virtual {v0, v3}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    invoke-direct {v2, v0}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 23
    .line 24
    .line 25
    const-string v0, "database"

    .line 26
    .line 27
    invoke-virtual {v2, v0}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    xor-int/lit8 v3, v0, 0x1

    .line 32
    .line 33
    const-string v4, "database/dup"

    .line 34
    .line 35
    invoke-virtual {v2, v4}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v4

    .line 39
    if-eqz v4, :cond_0

    .line 40
    .line 41
    move v0, v1

    .line 42
    move v3, v0

    .line 43
    :cond_0
    const-string v4, "code"

    .line 44
    .line 45
    invoke-virtual {v2, v4}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v4

    .line 49
    xor-int/lit8 v5, v4, 0x1

    .line 50
    .line 51
    const-string v6, "code/dup"

    .line 52
    .line 53
    invoke-virtual {v2, v6}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v2

    .line 57
    if-eqz v2, :cond_1

    .line 58
    .line 59
    move v4, v1

    .line 60
    move v5, v4

    .line 61
    :cond_1
    move v1, v3

    .line 62
    goto :goto_0

    .line 63
    :cond_2
    const/4 v0, 0x0

    .line 64
    move v4, v0

    .line 65
    move v5, v1

    .line 66
    :goto_0
    sput-boolean v1, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitOldDatabaseSemconv:Z

    .line 67
    .line 68
    sput-boolean v0, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitStableDatabaseSemconv:Z

    .line 69
    .line 70
    sput-boolean v5, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitOldCodeSemconv:Z

    .line 71
    .line 72
    sput-boolean v4, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitStableCodeSemconv:Z

    .line 73
    .line 74
    new-instance v0, Ljava/util/HashMap;

    .line 75
    .line 76
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 77
    .line 78
    .line 79
    sput-object v0, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->dbSystemNameMap:Ljava/util/Map;

    .line 80
    .line 81
    const-string v1, "adabas"

    .line 82
    .line 83
    const-string v2, "softwareag.adabas"

    .line 84
    .line 85
    invoke-interface {v0, v1, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    const-string v1, "intersystems_cache"

    .line 89
    .line 90
    const-string v2, "intersystems.cache"

    .line 91
    .line 92
    invoke-interface {v0, v1, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    const-string v1, "cosmosdb"

    .line 96
    .line 97
    const-string v2, "azure.cosmosdb"

    .line 98
    .line 99
    invoke-interface {v0, v1, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    const-string v1, "db2"

    .line 103
    .line 104
    const-string v2, "ibm.db2"

    .line 105
    .line 106
    invoke-interface {v0, v1, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    const-string v1, "dynamodb"

    .line 110
    .line 111
    const-string v2, "aws.dynamodb"

    .line 112
    .line 113
    invoke-interface {v0, v1, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    const-string v1, "h2"

    .line 117
    .line 118
    const-string v2, "h2database"

    .line 119
    .line 120
    invoke-interface {v0, v1, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    const-string v1, "hanadb"

    .line 124
    .line 125
    const-string v2, "sap.hana"

    .line 126
    .line 127
    invoke-interface {v0, v1, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    const-string v1, "informix"

    .line 131
    .line 132
    const-string v2, "ibm.informix"

    .line 133
    .line 134
    invoke-interface {v0, v1, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    const-string v1, "ingres"

    .line 138
    .line 139
    const-string v2, "actian.ingres"

    .line 140
    .line 141
    invoke-interface {v0, v1, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    const-string v1, "maxdb"

    .line 145
    .line 146
    const-string v2, "sap.maxdb"

    .line 147
    .line 148
    invoke-interface {v0, v1, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    const-string v1, "mssql"

    .line 152
    .line 153
    const-string v2, "microsoft.sql_server"

    .line 154
    .line 155
    invoke-interface {v0, v1, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    const-string v1, "netezza"

    .line 159
    .line 160
    const-string v2, "ibm.netezza"

    .line 161
    .line 162
    invoke-interface {v0, v1, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    const-string v1, "oracle"

    .line 166
    .line 167
    const-string v2, "oracle.db"

    .line 168
    .line 169
    invoke-interface {v0, v1, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    const-string v1, "redshift"

    .line 173
    .line 174
    const-string v2, "aws.redshift"

    .line 175
    .line 176
    invoke-interface {v0, v1, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    const-string v1, "spanner"

    .line 180
    .line 181
    const-string v2, "gcp.spanner"

    .line 182
    .line 183
    invoke-interface {v0, v1, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 184
    .line 185
    .line 186
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static emitOldDatabaseSemconv()Z
    .locals 1

    .line 1
    sget-boolean v0, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitOldDatabaseSemconv:Z

    .line 2
    .line 3
    return v0
.end method

.method public static emitStableDatabaseSemconv()Z
    .locals 1

    .line 1
    sget-boolean v0, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitStableDatabaseSemconv:Z

    .line 2
    .line 3
    return v0
.end method

.method public static isEmitOldCodeSemconv()Z
    .locals 1

    .line 1
    sget-boolean v0, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitOldCodeSemconv:Z

    .line 2
    .line 3
    return v0
.end method

.method public static isEmitStableCodeSemconv()Z
    .locals 1

    .line 1
    sget-boolean v0, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitStableCodeSemconv:Z

    .line 2
    .line 3
    return v0
.end method

.method public static stableDbSystemName(Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->dbSystemNameMap:Ljava/util/Map;

    .line 2
    .line 3
    invoke-interface {v0, p0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Ljava/lang/String;

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    return-object v0

    .line 12
    :cond_0
    return-object p0
.end method
