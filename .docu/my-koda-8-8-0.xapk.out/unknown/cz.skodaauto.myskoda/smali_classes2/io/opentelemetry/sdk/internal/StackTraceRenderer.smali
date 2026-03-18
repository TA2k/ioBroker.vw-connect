.class Lio/opentelemetry/sdk/internal/StackTraceRenderer;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final CAUSED_BY:Ljava/lang/String; = "Caused by: "

.field private static final SUPPRESSED:Ljava/lang/String; = "Suppressed: "


# instance fields
.field private final builder:Ljava/lang/StringBuilder;

.field private final lengthLimit:I

.field private final throwable:Ljava/lang/Throwable;


# direct methods
.method public constructor <init>(Ljava/lang/Throwable;I)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/lang/StringBuilder;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lio/opentelemetry/sdk/internal/StackTraceRenderer;->builder:Ljava/lang/StringBuilder;

    .line 10
    .line 11
    iput-object p1, p0, Lio/opentelemetry/sdk/internal/StackTraceRenderer;->throwable:Ljava/lang/Throwable;

    .line 12
    .line 13
    iput p2, p0, Lio/opentelemetry/sdk/internal/StackTraceRenderer;->lengthLimit:I

    .line 14
    .line 15
    return-void
.end method

.method private appendInnerStacktrace([Ljava/lang/StackTraceElement;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)Z
    .locals 9
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "([",
            "Ljava/lang/StackTraceElement;",
            "Ljava/lang/Throwable;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/util/Set<",
            "Ljava/lang/Throwable;",
            ">;)Z"
        }
    .end annotation

    .line 1
    invoke-interface {p5, p2}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x1

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    iget-object p0, p0, Lio/opentelemetry/sdk/internal/StackTraceRenderer;->builder:Ljava/lang/StringBuilder;

    .line 9
    .line 10
    invoke-virtual {p0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    const-string p1, "[CIRCULAR REFERENCE: "

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    const-string p1, "]"

    .line 25
    .line 26
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-static {}, Ljava/lang/System;->lineSeparator()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    return v1

    .line 37
    :cond_0
    invoke-interface {p5, p2}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    invoke-virtual {p2}, Ljava/lang/Throwable;->getStackTrace()[Ljava/lang/StackTraceElement;

    .line 41
    .line 42
    .line 43
    move-result-object v3

    .line 44
    array-length v0, p1

    .line 45
    sub-int/2addr v0, v1

    .line 46
    array-length v2, v3

    .line 47
    sub-int/2addr v2, v1

    .line 48
    :goto_0
    if-ltz v0, :cond_3

    .line 49
    .line 50
    if-gez v2, :cond_1

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_1
    aget-object v4, p1, v0

    .line 54
    .line 55
    aget-object v5, v3, v2

    .line 56
    .line 57
    invoke-virtual {v4, v5}, Ljava/lang/StackTraceElement;->equals(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v4

    .line 61
    if-nez v4, :cond_2

    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_2
    add-int/lit8 v0, v0, -0x1

    .line 65
    .line 66
    add-int/lit8 v2, v2, -0x1

    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_3
    :goto_1
    iget-object p1, p0, Lio/opentelemetry/sdk/internal/StackTraceRenderer;->builder:Ljava/lang/StringBuilder;

    .line 70
    .line 71
    invoke-virtual {p1, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    invoke-virtual {p1, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    invoke-static {}, Ljava/lang/System;->lineSeparator()Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object p4

    .line 84
    invoke-virtual {p1, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    invoke-direct {p0}, Lio/opentelemetry/sdk/internal/StackTraceRenderer;->isOverLimit()Z

    .line 88
    .line 89
    .line 90
    move-result p1

    .line 91
    if-eqz p1, :cond_4

    .line 92
    .line 93
    return v1

    .line 94
    :cond_4
    const/4 p1, 0x0

    .line 95
    move p4, p1

    .line 96
    :goto_2
    if-gt p4, v2, :cond_6

    .line 97
    .line 98
    aget-object v0, v3, p4

    .line 99
    .line 100
    iget-object v4, p0, Lio/opentelemetry/sdk/internal/StackTraceRenderer;->builder:Ljava/lang/StringBuilder;

    .line 101
    .line 102
    invoke-virtual {v4, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    const-string v5, "\tat "

    .line 106
    .line 107
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 108
    .line 109
    .line 110
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    invoke-static {}, Ljava/lang/System;->lineSeparator()Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object v0

    .line 117
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 118
    .line 119
    .line 120
    invoke-direct {p0}, Lio/opentelemetry/sdk/internal/StackTraceRenderer;->isOverLimit()Z

    .line 121
    .line 122
    .line 123
    move-result v0

    .line 124
    if-eqz v0, :cond_5

    .line 125
    .line 126
    return v1

    .line 127
    :cond_5
    add-int/lit8 p4, p4, 0x1

    .line 128
    .line 129
    goto :goto_2

    .line 130
    :cond_6
    array-length p4, v3

    .line 131
    sub-int/2addr p4, v1

    .line 132
    sub-int/2addr p4, v2

    .line 133
    if-eqz p4, :cond_7

    .line 134
    .line 135
    iget-object v0, p0, Lio/opentelemetry/sdk/internal/StackTraceRenderer;->builder:Ljava/lang/StringBuilder;

    .line 136
    .line 137
    invoke-virtual {v0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 138
    .line 139
    .line 140
    const-string v2, "\t... "

    .line 141
    .line 142
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 143
    .line 144
    .line 145
    invoke-virtual {v0, p4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 146
    .line 147
    .line 148
    const-string p4, " more"

    .line 149
    .line 150
    invoke-virtual {v0, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 151
    .line 152
    .line 153
    invoke-static {}, Ljava/lang/System;->lineSeparator()Ljava/lang/String;

    .line 154
    .line 155
    .line 156
    move-result-object p4

    .line 157
    invoke-virtual {v0, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 158
    .line 159
    .line 160
    invoke-direct {p0}, Lio/opentelemetry/sdk/internal/StackTraceRenderer;->isOverLimit()Z

    .line 161
    .line 162
    .line 163
    move-result p4

    .line 164
    if-eqz p4, :cond_7

    .line 165
    .line 166
    return v1

    .line 167
    :cond_7
    invoke-virtual {p2}, Ljava/lang/Throwable;->getSuppressed()[Ljava/lang/Throwable;

    .line 168
    .line 169
    .line 170
    move-result-object p4

    .line 171
    array-length v0, p4

    .line 172
    move v8, p1

    .line 173
    :goto_3
    if-ge v8, v0, :cond_9

    .line 174
    .line 175
    aget-object v4, p4, v8

    .line 176
    .line 177
    const-string v2, "\t"

    .line 178
    .line 179
    invoke-static {p3, v2}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 180
    .line 181
    .line 182
    move-result-object v5

    .line 183
    const-string v6, "Suppressed: "

    .line 184
    .line 185
    move-object v2, p0

    .line 186
    move-object v7, p5

    .line 187
    invoke-direct/range {v2 .. v7}, Lio/opentelemetry/sdk/internal/StackTraceRenderer;->appendInnerStacktrace([Ljava/lang/StackTraceElement;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)Z

    .line 188
    .line 189
    .line 190
    move-result p0

    .line 191
    if-eqz p0, :cond_8

    .line 192
    .line 193
    return v1

    .line 194
    :cond_8
    add-int/lit8 v8, v8, 0x1

    .line 195
    .line 196
    move-object p0, v2

    .line 197
    move-object p5, v7

    .line 198
    goto :goto_3

    .line 199
    :cond_9
    move-object v2, p0

    .line 200
    move-object v7, p5

    .line 201
    invoke-virtual {p2}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 202
    .line 203
    .line 204
    move-result-object v4

    .line 205
    if-eqz v4, :cond_a

    .line 206
    .line 207
    const-string v6, "Caused by: "

    .line 208
    .line 209
    move-object v5, p3

    .line 210
    invoke-direct/range {v2 .. v7}, Lio/opentelemetry/sdk/internal/StackTraceRenderer;->appendInnerStacktrace([Ljava/lang/StackTraceElement;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)Z

    .line 211
    .line 212
    .line 213
    move-result p0

    .line 214
    return p0

    .line 215
    :cond_a
    return p1
.end method

.method private appendStackTrace()V
    .locals 9

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/internal/StackTraceRenderer;->builder:Ljava/lang/StringBuilder;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/sdk/internal/StackTraceRenderer;->throwable:Ljava/lang/Throwable;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 6
    .line 7
    .line 8
    invoke-static {}, Ljava/lang/System;->lineSeparator()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    invoke-direct {p0}, Lio/opentelemetry/sdk/internal/StackTraceRenderer;->isOverLimit()Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    goto :goto_2

    .line 22
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/sdk/internal/StackTraceRenderer;->throwable:Ljava/lang/Throwable;

    .line 23
    .line 24
    invoke-virtual {v0}, Ljava/lang/Throwable;->getStackTrace()[Ljava/lang/StackTraceElement;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    array-length v0, v2

    .line 29
    const/4 v1, 0x0

    .line 30
    move v3, v1

    .line 31
    :goto_0
    if-ge v3, v0, :cond_2

    .line 32
    .line 33
    aget-object v4, v2, v3

    .line 34
    .line 35
    iget-object v5, p0, Lio/opentelemetry/sdk/internal/StackTraceRenderer;->builder:Ljava/lang/StringBuilder;

    .line 36
    .line 37
    const-string v6, "\tat "

    .line 38
    .line 39
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    invoke-static {}, Ljava/lang/System;->lineSeparator()Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object v4

    .line 49
    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-direct {p0}, Lio/opentelemetry/sdk/internal/StackTraceRenderer;->isOverLimit()Z

    .line 53
    .line 54
    .line 55
    move-result v4

    .line 56
    if-eqz v4, :cond_1

    .line 57
    .line 58
    goto :goto_2

    .line 59
    :cond_1
    add-int/lit8 v3, v3, 0x1

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_2
    new-instance v0, Ljava/util/IdentityHashMap;

    .line 63
    .line 64
    invoke-direct {v0}, Ljava/util/IdentityHashMap;-><init>()V

    .line 65
    .line 66
    .line 67
    invoke-static {v0}, Ljava/util/Collections;->newSetFromMap(Ljava/util/Map;)Ljava/util/Set;

    .line 68
    .line 69
    .line 70
    move-result-object v6

    .line 71
    iget-object v0, p0, Lio/opentelemetry/sdk/internal/StackTraceRenderer;->throwable:Ljava/lang/Throwable;

    .line 72
    .line 73
    invoke-interface {v6, v0}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    iget-object v0, p0, Lio/opentelemetry/sdk/internal/StackTraceRenderer;->throwable:Ljava/lang/Throwable;

    .line 77
    .line 78
    invoke-virtual {v0}, Ljava/lang/Throwable;->getSuppressed()[Ljava/lang/Throwable;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    array-length v7, v0

    .line 83
    move v8, v1

    .line 84
    :goto_1
    if-ge v8, v7, :cond_3

    .line 85
    .line 86
    aget-object v3, v0, v8

    .line 87
    .line 88
    const-string v4, "\t"

    .line 89
    .line 90
    const-string v5, "Suppressed: "

    .line 91
    .line 92
    move-object v1, p0

    .line 93
    invoke-direct/range {v1 .. v6}, Lio/opentelemetry/sdk/internal/StackTraceRenderer;->appendInnerStacktrace([Ljava/lang/StackTraceElement;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)Z

    .line 94
    .line 95
    .line 96
    add-int/lit8 v8, v8, 0x1

    .line 97
    .line 98
    goto :goto_1

    .line 99
    :cond_3
    move-object v1, p0

    .line 100
    iget-object p0, v1, Lio/opentelemetry/sdk/internal/StackTraceRenderer;->throwable:Ljava/lang/Throwable;

    .line 101
    .line 102
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 103
    .line 104
    .line 105
    move-result-object v3

    .line 106
    if-eqz v3, :cond_4

    .line 107
    .line 108
    const-string v4, ""

    .line 109
    .line 110
    const-string v5, "Caused by: "

    .line 111
    .line 112
    invoke-direct/range {v1 .. v6}, Lio/opentelemetry/sdk/internal/StackTraceRenderer;->appendInnerStacktrace([Ljava/lang/StackTraceElement;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)Z

    .line 113
    .line 114
    .line 115
    :cond_4
    :goto_2
    return-void
.end method

.method private isOverLimit()Z
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/internal/StackTraceRenderer;->builder:Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->length()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget p0, p0, Lio/opentelemetry/sdk/internal/StackTraceRenderer;->lengthLimit:I

    .line 8
    .line 9
    if-lt v0, p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method


# virtual methods
.method public render()Ljava/lang/String;
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/internal/StackTraceRenderer;->builder:Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->length()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    invoke-direct {p0}, Lio/opentelemetry/sdk/internal/StackTraceRenderer;->appendStackTrace()V

    .line 10
    .line 11
    .line 12
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/sdk/internal/StackTraceRenderer;->builder:Ljava/lang/StringBuilder;

    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->length()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    iget p0, p0, Lio/opentelemetry/sdk/internal/StackTraceRenderer;->lengthLimit:I

    .line 19
    .line 20
    invoke-static {v1, p0}, Ljava/lang/Math;->min(II)I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    const/4 v1, 0x0

    .line 25
    invoke-virtual {v0, v1, p0}, Ljava/lang/StringBuilder;->substring(II)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method
