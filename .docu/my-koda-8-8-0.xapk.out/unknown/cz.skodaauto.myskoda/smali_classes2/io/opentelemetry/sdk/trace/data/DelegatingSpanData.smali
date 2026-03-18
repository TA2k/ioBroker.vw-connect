.class public abstract Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/trace/data/SpanData;


# instance fields
.field private final delegate:Lio/opentelemetry/sdk/trace/data/SpanData;


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/trace/data/SpanData;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "delegate"

    .line 5
    .line 6
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    check-cast p1, Lio/opentelemetry/sdk/trace/data/SpanData;

    .line 10
    .line 11
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->delegate:Lio/opentelemetry/sdk/trace/data/SpanData;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public equals(Ljava/lang/Object;)Z
    .locals 7
    .param p1    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p1, p0, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lio/opentelemetry/sdk/trace/data/SpanData;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    check-cast p1, Lio/opentelemetry/sdk/trace/data/SpanData;

    .line 11
    .line 12
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 17
    .line 18
    .line 19
    move-result-object v3

    .line 20
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    if-eqz v1, :cond_1

    .line 25
    .line 26
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getParentSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getParentSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 31
    .line 32
    .line 33
    move-result-object v3

    .line 34
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-eqz v1, :cond_1

    .line 39
    .line 40
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getResource()Lio/opentelemetry/sdk/resources/Resource;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getResource()Lio/opentelemetry/sdk/resources/Resource;

    .line 45
    .line 46
    .line 47
    move-result-object v3

    .line 48
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v1

    .line 52
    if-eqz v1, :cond_1

    .line 53
    .line 54
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 59
    .line 60
    .line 61
    move-result-object v3

    .line 62
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result v1

    .line 66
    if-eqz v1, :cond_1

    .line 67
    .line 68
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getName()Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getName()Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object v3

    .line 76
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result v1

    .line 80
    if-eqz v1, :cond_1

    .line 81
    .line 82
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getKind()Lio/opentelemetry/api/trace/SpanKind;

    .line 83
    .line 84
    .line 85
    move-result-object v1

    .line 86
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getKind()Lio/opentelemetry/api/trace/SpanKind;

    .line 87
    .line 88
    .line 89
    move-result-object v3

    .line 90
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result v1

    .line 94
    if-eqz v1, :cond_1

    .line 95
    .line 96
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getStartEpochNanos()J

    .line 97
    .line 98
    .line 99
    move-result-wide v3

    .line 100
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getStartEpochNanos()J

    .line 101
    .line 102
    .line 103
    move-result-wide v5

    .line 104
    cmp-long v1, v3, v5

    .line 105
    .line 106
    if-nez v1, :cond_1

    .line 107
    .line 108
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 109
    .line 110
    .line 111
    move-result-object v1

    .line 112
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 113
    .line 114
    .line 115
    move-result-object v3

    .line 116
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    move-result v1

    .line 120
    if-eqz v1, :cond_1

    .line 121
    .line 122
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getEvents()Ljava/util/List;

    .line 123
    .line 124
    .line 125
    move-result-object v1

    .line 126
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getEvents()Ljava/util/List;

    .line 127
    .line 128
    .line 129
    move-result-object v3

    .line 130
    invoke-interface {v1, v3}, Ljava/util/List;->equals(Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result v1

    .line 134
    if-eqz v1, :cond_1

    .line 135
    .line 136
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getLinks()Ljava/util/List;

    .line 137
    .line 138
    .line 139
    move-result-object v1

    .line 140
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getLinks()Ljava/util/List;

    .line 141
    .line 142
    .line 143
    move-result-object v3

    .line 144
    invoke-interface {v1, v3}, Ljava/util/List;->equals(Ljava/lang/Object;)Z

    .line 145
    .line 146
    .line 147
    move-result v1

    .line 148
    if-eqz v1, :cond_1

    .line 149
    .line 150
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getStatus()Lio/opentelemetry/sdk/trace/data/StatusData;

    .line 151
    .line 152
    .line 153
    move-result-object v1

    .line 154
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getStatus()Lio/opentelemetry/sdk/trace/data/StatusData;

    .line 155
    .line 156
    .line 157
    move-result-object v3

    .line 158
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 159
    .line 160
    .line 161
    move-result v1

    .line 162
    if-eqz v1, :cond_1

    .line 163
    .line 164
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getEndEpochNanos()J

    .line 165
    .line 166
    .line 167
    move-result-wide v3

    .line 168
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getEndEpochNanos()J

    .line 169
    .line 170
    .line 171
    move-result-wide v5

    .line 172
    cmp-long v1, v3, v5

    .line 173
    .line 174
    if-nez v1, :cond_1

    .line 175
    .line 176
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->hasEnded()Z

    .line 177
    .line 178
    .line 179
    move-result v1

    .line 180
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->hasEnded()Z

    .line 181
    .line 182
    .line 183
    move-result v3

    .line 184
    if-ne v1, v3, :cond_1

    .line 185
    .line 186
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getTotalRecordedEvents()I

    .line 187
    .line 188
    .line 189
    move-result v1

    .line 190
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getTotalRecordedEvents()I

    .line 191
    .line 192
    .line 193
    move-result v3

    .line 194
    if-ne v1, v3, :cond_1

    .line 195
    .line 196
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getTotalRecordedLinks()I

    .line 197
    .line 198
    .line 199
    move-result v1

    .line 200
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getTotalRecordedLinks()I

    .line 201
    .line 202
    .line 203
    move-result v3

    .line 204
    if-ne v1, v3, :cond_1

    .line 205
    .line 206
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getTotalAttributeCount()I

    .line 207
    .line 208
    .line 209
    move-result p0

    .line 210
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getTotalAttributeCount()I

    .line 211
    .line 212
    .line 213
    move-result p1

    .line 214
    if-ne p0, p1, :cond_1

    .line 215
    .line 216
    return v0

    .line 217
    :cond_1
    return v2
.end method

.method public getAttributes()Lio/opentelemetry/api/common/Attributes;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->delegate:Lio/opentelemetry/sdk/trace/data/SpanData;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getEndEpochNanos()J
    .locals 2

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->delegate:Lio/opentelemetry/sdk/trace/data/SpanData;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getEndEpochNanos()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    return-wide v0
.end method

.method public getEvents()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/trace/data/EventData;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->delegate:Lio/opentelemetry/sdk/trace/data/SpanData;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getEvents()Ljava/util/List;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getInstrumentationLibraryInfo()Lio/opentelemetry/sdk/common/InstrumentationLibraryInfo;
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->delegate:Lio/opentelemetry/sdk/trace/data/SpanData;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getInstrumentationLibraryInfo()Lio/opentelemetry/sdk/common/InstrumentationLibraryInfo;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->delegate:Lio/opentelemetry/sdk/trace/data/SpanData;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getKind()Lio/opentelemetry/api/trace/SpanKind;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->delegate:Lio/opentelemetry/sdk/trace/data/SpanData;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getKind()Lio/opentelemetry/api/trace/SpanKind;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getLinks()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/trace/data/LinkData;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->delegate:Lio/opentelemetry/sdk/trace/data/SpanData;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getLinks()Ljava/util/List;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->delegate:Lio/opentelemetry/sdk/trace/data/SpanData;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getParentSpanContext()Lio/opentelemetry/api/trace/SpanContext;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->delegate:Lio/opentelemetry/sdk/trace/data/SpanData;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getParentSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getResource()Lio/opentelemetry/sdk/resources/Resource;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->delegate:Lio/opentelemetry/sdk/trace/data/SpanData;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getResource()Lio/opentelemetry/sdk/resources/Resource;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getSpanContext()Lio/opentelemetry/api/trace/SpanContext;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->delegate:Lio/opentelemetry/sdk/trace/data/SpanData;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getStartEpochNanos()J
    .locals 2

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->delegate:Lio/opentelemetry/sdk/trace/data/SpanData;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getStartEpochNanos()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    return-wide v0
.end method

.method public getStatus()Lio/opentelemetry/sdk/trace/data/StatusData;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->delegate:Lio/opentelemetry/sdk/trace/data/SpanData;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getStatus()Lio/opentelemetry/sdk/trace/data/StatusData;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getTotalAttributeCount()I
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->delegate:Lio/opentelemetry/sdk/trace/data/SpanData;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getTotalAttributeCount()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getTotalRecordedEvents()I
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->delegate:Lio/opentelemetry/sdk/trace/data/SpanData;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getTotalRecordedEvents()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getTotalRecordedLinks()I
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->delegate:Lio/opentelemetry/sdk/trace/data/SpanData;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->getTotalRecordedLinks()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public hasEnded()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->delegate:Lio/opentelemetry/sdk/trace/data/SpanData;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/data/SpanData;->hasEnded()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public hashCode()I
    .locals 7

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const v1, 0xf4243

    .line 10
    .line 11
    .line 12
    xor-int/2addr v0, v1

    .line 13
    mul-int/2addr v0, v1

    .line 14
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getParentSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    xor-int/2addr v0, v2

    .line 23
    mul-int/2addr v0, v1

    .line 24
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getResource()Lio/opentelemetry/sdk/resources/Resource;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    xor-int/2addr v0, v2

    .line 33
    mul-int/2addr v0, v1

    .line 34
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 39
    .line 40
    .line 41
    move-result v2

    .line 42
    xor-int/2addr v0, v2

    .line 43
    mul-int/2addr v0, v1

    .line 44
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getName()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    xor-int/2addr v0, v2

    .line 53
    mul-int/2addr v0, v1

    .line 54
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getKind()Lio/opentelemetry/api/trace/SpanKind;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 59
    .line 60
    .line 61
    move-result v2

    .line 62
    xor-int/2addr v0, v2

    .line 63
    mul-int/2addr v0, v1

    .line 64
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getStartEpochNanos()J

    .line 65
    .line 66
    .line 67
    move-result-wide v2

    .line 68
    const/16 v4, 0x20

    .line 69
    .line 70
    ushr-long/2addr v2, v4

    .line 71
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getStartEpochNanos()J

    .line 72
    .line 73
    .line 74
    move-result-wide v5

    .line 75
    xor-long/2addr v2, v5

    .line 76
    long-to-int v2, v2

    .line 77
    xor-int/2addr v0, v2

    .line 78
    mul-int/2addr v0, v1

    .line 79
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 80
    .line 81
    .line 82
    move-result-object v2

    .line 83
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 84
    .line 85
    .line 86
    move-result v2

    .line 87
    xor-int/2addr v0, v2

    .line 88
    mul-int/2addr v0, v1

    .line 89
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getEvents()Ljava/util/List;

    .line 90
    .line 91
    .line 92
    move-result-object v2

    .line 93
    invoke-interface {v2}, Ljava/util/List;->hashCode()I

    .line 94
    .line 95
    .line 96
    move-result v2

    .line 97
    xor-int/2addr v0, v2

    .line 98
    mul-int/2addr v0, v1

    .line 99
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getLinks()Ljava/util/List;

    .line 100
    .line 101
    .line 102
    move-result-object v2

    .line 103
    invoke-interface {v2}, Ljava/util/List;->hashCode()I

    .line 104
    .line 105
    .line 106
    move-result v2

    .line 107
    xor-int/2addr v0, v2

    .line 108
    mul-int/2addr v0, v1

    .line 109
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getStatus()Lio/opentelemetry/sdk/trace/data/StatusData;

    .line 110
    .line 111
    .line 112
    move-result-object v2

    .line 113
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 114
    .line 115
    .line 116
    move-result v2

    .line 117
    xor-int/2addr v0, v2

    .line 118
    mul-int/2addr v0, v1

    .line 119
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getEndEpochNanos()J

    .line 120
    .line 121
    .line 122
    move-result-wide v2

    .line 123
    ushr-long/2addr v2, v4

    .line 124
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getEndEpochNanos()J

    .line 125
    .line 126
    .line 127
    move-result-wide v4

    .line 128
    xor-long/2addr v2, v4

    .line 129
    long-to-int v2, v2

    .line 130
    xor-int/2addr v0, v2

    .line 131
    mul-int/2addr v0, v1

    .line 132
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->hasEnded()Z

    .line 133
    .line 134
    .line 135
    move-result v2

    .line 136
    if-eqz v2, :cond_0

    .line 137
    .line 138
    const/16 v2, 0x4cf

    .line 139
    .line 140
    goto :goto_0

    .line 141
    :cond_0
    const/16 v2, 0x4d5

    .line 142
    .line 143
    :goto_0
    xor-int/2addr v0, v2

    .line 144
    mul-int/2addr v0, v1

    .line 145
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getTotalRecordedEvents()I

    .line 146
    .line 147
    .line 148
    move-result v2

    .line 149
    xor-int/2addr v0, v2

    .line 150
    mul-int/2addr v0, v1

    .line 151
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getTotalRecordedLinks()I

    .line 152
    .line 153
    .line 154
    move-result v2

    .line 155
    xor-int/2addr v0, v2

    .line 156
    mul-int/2addr v0, v1

    .line 157
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getTotalAttributeCount()I

    .line 158
    .line 159
    .line 160
    move-result p0

    .line 161
    xor-int/2addr p0, v0

    .line 162
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "DelegatingSpanData{spanContext="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string v1, ", parentSpanContext="

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getParentSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const-string v1, ", resource="

    .line 28
    .line 29
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getResource()Lio/opentelemetry/sdk/resources/Resource;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    const-string v1, ", instrumentationScopeInfo="

    .line 40
    .line 41
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    const-string v1, ", name="

    .line 52
    .line 53
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getName()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", kind="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getKind()Lio/opentelemetry/api/trace/SpanKind;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    const-string v1, ", startEpochNanos="

    .line 76
    .line 77
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getStartEpochNanos()J

    .line 81
    .line 82
    .line 83
    move-result-wide v1

    .line 84
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    const-string v1, ", attributes="

    .line 88
    .line 89
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 93
    .line 94
    .line 95
    move-result-object v1

    .line 96
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    const-string v1, ", events="

    .line 100
    .line 101
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 102
    .line 103
    .line 104
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getEvents()Ljava/util/List;

    .line 105
    .line 106
    .line 107
    move-result-object v1

    .line 108
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 109
    .line 110
    .line 111
    const-string v1, ", links="

    .line 112
    .line 113
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 114
    .line 115
    .line 116
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getLinks()Ljava/util/List;

    .line 117
    .line 118
    .line 119
    move-result-object v1

    .line 120
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 121
    .line 122
    .line 123
    const-string v1, ", status="

    .line 124
    .line 125
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getStatus()Lio/opentelemetry/sdk/trace/data/StatusData;

    .line 129
    .line 130
    .line 131
    move-result-object v1

    .line 132
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 133
    .line 134
    .line 135
    const-string v1, ", endEpochNanos="

    .line 136
    .line 137
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 138
    .line 139
    .line 140
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getEndEpochNanos()J

    .line 141
    .line 142
    .line 143
    move-result-wide v1

    .line 144
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 145
    .line 146
    .line 147
    const-string v1, ", hasEnded="

    .line 148
    .line 149
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 150
    .line 151
    .line 152
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->hasEnded()Z

    .line 153
    .line 154
    .line 155
    move-result v1

    .line 156
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 157
    .line 158
    .line 159
    const-string v1, ", totalRecordedEvents="

    .line 160
    .line 161
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 162
    .line 163
    .line 164
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getTotalRecordedEvents()I

    .line 165
    .line 166
    .line 167
    move-result v1

    .line 168
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 169
    .line 170
    .line 171
    const-string v1, ", totalRecordedLinks="

    .line 172
    .line 173
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 174
    .line 175
    .line 176
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getTotalRecordedLinks()I

    .line 177
    .line 178
    .line 179
    move-result v1

    .line 180
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 181
    .line 182
    .line 183
    const-string v1, ", totalAttributeCount="

    .line 184
    .line 185
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 186
    .line 187
    .line 188
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/data/DelegatingSpanData;->getTotalAttributeCount()I

    .line 189
    .line 190
    .line 191
    move-result p0

    .line 192
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 193
    .line 194
    .line 195
    const-string p0, "}"

    .line 196
    .line 197
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 198
    .line 199
    .line 200
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 201
    .line 202
    .line 203
    move-result-object p0

    .line 204
    return-object p0
.end method
