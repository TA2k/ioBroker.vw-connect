.class public final Lp6/g;
.super Landroidx/datastore/preferences/protobuf/x;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final DEFAULT_INSTANCE:Lp6/g;

.field private static volatile PARSER:Landroidx/datastore/preferences/protobuf/v0; = null
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroidx/datastore/preferences/protobuf/v0;"
        }
    .end annotation
.end field

.field public static final STRINGS_FIELD_NUMBER:I = 0x1


# instance fields
.field private strings_:Landroidx/datastore/preferences/protobuf/z;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroidx/datastore/preferences/protobuf/z;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lp6/g;

    .line 2
    .line 3
    invoke-direct {v0}, Lp6/g;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lp6/g;->DEFAULT_INSTANCE:Lp6/g;

    .line 7
    .line 8
    const-class v1, Lp6/g;

    .line 9
    .line 10
    invoke-static {v1, v0}, Landroidx/datastore/preferences/protobuf/x;->j(Ljava/lang/Class;Landroidx/datastore/preferences/protobuf/x;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Landroidx/datastore/preferences/protobuf/x;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Landroidx/datastore/preferences/protobuf/y0;->g:Landroidx/datastore/preferences/protobuf/y0;

    .line 5
    .line 6
    iput-object v0, p0, Lp6/g;->strings_:Landroidx/datastore/preferences/protobuf/z;

    .line 7
    .line 8
    return-void
.end method

.method public static l(Lp6/g;Ljava/lang/Iterable;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lp6/g;->strings_:Landroidx/datastore/preferences/protobuf/z;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Landroidx/datastore/preferences/protobuf/b;

    .line 5
    .line 6
    iget-boolean v1, v1, Landroidx/datastore/preferences/protobuf/b;->d:Z

    .line 7
    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-nez v1, :cond_0

    .line 15
    .line 16
    const/16 v1, 0xa

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    mul-int/lit8 v1, v1, 0x2

    .line 20
    .line 21
    :goto_0
    check-cast v0, Landroidx/datastore/preferences/protobuf/y0;

    .line 22
    .line 23
    invoke-virtual {v0, v1}, Landroidx/datastore/preferences/protobuf/y0;->g(I)Landroidx/datastore/preferences/protobuf/y0;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    iput-object v0, p0, Lp6/g;->strings_:Landroidx/datastore/preferences/protobuf/z;

    .line 28
    .line 29
    :cond_1
    iget-object p0, p0, Lp6/g;->strings_:Landroidx/datastore/preferences/protobuf/z;

    .line 30
    .line 31
    sget-object v0, Landroidx/datastore/preferences/protobuf/a0;->a:Ljava/nio/charset/Charset;

    .line 32
    .line 33
    instance-of v0, p1, Landroidx/datastore/preferences/protobuf/e0;

    .line 34
    .line 35
    if-eqz v0, :cond_5

    .line 36
    .line 37
    check-cast p1, Landroidx/datastore/preferences/protobuf/e0;

    .line 38
    .line 39
    invoke-interface {p1}, Landroidx/datastore/preferences/protobuf/e0;->getUnderlyingElements()Ljava/util/List;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    if-nez p0, :cond_4

    .line 44
    .line 45
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 46
    .line 47
    .line 48
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 53
    .line 54
    .line 55
    move-result p1

    .line 56
    if-eqz p1, :cond_a

    .line 57
    .line 58
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 63
    .line 64
    .line 65
    instance-of p1, p0, Landroidx/datastore/preferences/protobuf/h;

    .line 66
    .line 67
    const/4 v0, 0x0

    .line 68
    if-nez p1, :cond_3

    .line 69
    .line 70
    instance-of p1, p0, [B

    .line 71
    .line 72
    if-eqz p1, :cond_2

    .line 73
    .line 74
    check-cast p0, [B

    .line 75
    .line 76
    const/4 p1, 0x0

    .line 77
    array-length v1, p0

    .line 78
    invoke-static {p0, p1, v1}, Landroidx/datastore/preferences/protobuf/h;->g([BII)Landroidx/datastore/preferences/protobuf/h;

    .line 79
    .line 80
    .line 81
    throw v0

    .line 82
    :cond_2
    check-cast p0, Ljava/lang/String;

    .line 83
    .line 84
    throw v0

    .line 85
    :cond_3
    check-cast p0, Landroidx/datastore/preferences/protobuf/h;

    .line 86
    .line 87
    throw v0

    .line 88
    :cond_4
    new-instance p0, Ljava/lang/ClassCastException;

    .line 89
    .line 90
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 91
    .line 92
    .line 93
    throw p0

    .line 94
    :cond_5
    instance-of v0, p1, Landroidx/datastore/preferences/protobuf/w0;

    .line 95
    .line 96
    if-eqz v0, :cond_6

    .line 97
    .line 98
    check-cast p1, Ljava/util/Collection;

    .line 99
    .line 100
    invoke-interface {p0, p1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    .line 101
    .line 102
    .line 103
    return-void

    .line 104
    :cond_6
    instance-of v0, p0, Ljava/util/ArrayList;

    .line 105
    .line 106
    if-eqz v0, :cond_7

    .line 107
    .line 108
    instance-of v0, p1, Ljava/util/Collection;

    .line 109
    .line 110
    if-eqz v0, :cond_7

    .line 111
    .line 112
    move-object v0, p0

    .line 113
    check-cast v0, Ljava/util/ArrayList;

    .line 114
    .line 115
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 116
    .line 117
    .line 118
    move-result v1

    .line 119
    move-object v2, p1

    .line 120
    check-cast v2, Ljava/util/Collection;

    .line 121
    .line 122
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 123
    .line 124
    .line 125
    move-result v2

    .line 126
    add-int/2addr v2, v1

    .line 127
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->ensureCapacity(I)V

    .line 128
    .line 129
    .line 130
    :cond_7
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 131
    .line 132
    .line 133
    move-result v0

    .line 134
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 135
    .line 136
    .line 137
    move-result-object p1

    .line 138
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 139
    .line 140
    .line 141
    move-result v1

    .line 142
    if-eqz v1, :cond_a

    .line 143
    .line 144
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v1

    .line 148
    if-nez v1, :cond_9

    .line 149
    .line 150
    new-instance p1, Ljava/lang/StringBuilder;

    .line 151
    .line 152
    const-string v1, "Element at index "

    .line 153
    .line 154
    invoke-direct {p1, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 155
    .line 156
    .line 157
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 158
    .line 159
    .line 160
    move-result v1

    .line 161
    sub-int/2addr v1, v0

    .line 162
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 163
    .line 164
    .line 165
    const-string v1, " is null."

    .line 166
    .line 167
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 168
    .line 169
    .line 170
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 171
    .line 172
    .line 173
    move-result-object p1

    .line 174
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 175
    .line 176
    .line 177
    move-result v1

    .line 178
    add-int/lit8 v1, v1, -0x1

    .line 179
    .line 180
    :goto_2
    if-lt v1, v0, :cond_8

    .line 181
    .line 182
    invoke-interface {p0, v1}, Ljava/util/List;->remove(I)Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    add-int/lit8 v1, v1, -0x1

    .line 186
    .line 187
    goto :goto_2

    .line 188
    :cond_8
    new-instance p0, Ljava/lang/NullPointerException;

    .line 189
    .line 190
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    throw p0

    .line 194
    :cond_9
    invoke-interface {p0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 195
    .line 196
    .line 197
    goto :goto_1

    .line 198
    :cond_a
    return-void
.end method

.method public static m()Lp6/g;
    .locals 1

    .line 1
    sget-object v0, Lp6/g;->DEFAULT_INSTANCE:Lp6/g;

    .line 2
    .line 3
    return-object v0
.end method

.method public static o()Lp6/f;
    .locals 2

    .line 1
    sget-object v0, Lp6/g;->DEFAULT_INSTANCE:Lp6/g;

    .line 2
    .line 3
    const/4 v1, 0x5

    .line 4
    invoke-virtual {v0, v1}, Lp6/g;->c(I)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    check-cast v0, Landroidx/datastore/preferences/protobuf/v;

    .line 9
    .line 10
    check-cast v0, Lp6/f;

    .line 11
    .line 12
    return-object v0
.end method


# virtual methods
.method public final c(I)Ljava/lang/Object;
    .locals 2

    .line 1
    invoke-static {p1}, Lu/w;->o(I)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    packed-switch p0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 9
    .line 10
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 11
    .line 12
    .line 13
    throw p0

    .line 14
    :pswitch_0
    sget-object p0, Lp6/g;->PARSER:Landroidx/datastore/preferences/protobuf/v0;

    .line 15
    .line 16
    if-nez p0, :cond_1

    .line 17
    .line 18
    const-class p1, Lp6/g;

    .line 19
    .line 20
    monitor-enter p1

    .line 21
    :try_start_0
    sget-object p0, Lp6/g;->PARSER:Landroidx/datastore/preferences/protobuf/v0;

    .line 22
    .line 23
    if-nez p0, :cond_0

    .line 24
    .line 25
    new-instance p0, Landroidx/datastore/preferences/protobuf/w;

    .line 26
    .line 27
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 28
    .line 29
    .line 30
    sput-object p0, Lp6/g;->PARSER:Landroidx/datastore/preferences/protobuf/v0;

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :catchall_0
    move-exception p0

    .line 34
    goto :goto_1

    .line 35
    :cond_0
    :goto_0
    monitor-exit p1

    .line 36
    return-object p0

    .line 37
    :goto_1
    monitor-exit p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 38
    throw p0

    .line 39
    :cond_1
    return-object p0

    .line 40
    :pswitch_1
    sget-object p0, Lp6/g;->DEFAULT_INSTANCE:Lp6/g;

    .line 41
    .line 42
    return-object p0

    .line 43
    :pswitch_2
    new-instance p0, Lp6/f;

    .line 44
    .line 45
    sget-object p1, Lp6/g;->DEFAULT_INSTANCE:Lp6/g;

    .line 46
    .line 47
    invoke-direct {p0, p1}, Landroidx/datastore/preferences/protobuf/v;-><init>(Landroidx/datastore/preferences/protobuf/x;)V

    .line 48
    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_3
    new-instance p0, Lp6/g;

    .line 52
    .line 53
    invoke-direct {p0}, Lp6/g;-><init>()V

    .line 54
    .line 55
    .line 56
    return-object p0

    .line 57
    :pswitch_4
    const-string p0, "strings_"

    .line 58
    .line 59
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    const-string p1, "\u0001\u0001\u0000\u0000\u0001\u0001\u0001\u0000\u0001\u0000\u0001\u001a"

    .line 64
    .line 65
    sget-object v0, Lp6/g;->DEFAULT_INSTANCE:Lp6/g;

    .line 66
    .line 67
    new-instance v1, Landroidx/datastore/preferences/protobuf/z0;

    .line 68
    .line 69
    invoke-direct {v1, v0, p1, p0}, Landroidx/datastore/preferences/protobuf/z0;-><init>(Landroidx/datastore/preferences/protobuf/x;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    return-object v1

    .line 73
    :pswitch_5
    const/4 p0, 0x0

    .line 74
    return-object p0

    .line 75
    :pswitch_6
    const/4 p0, 0x1

    .line 76
    invoke-static {p0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    return-object p0

    .line 81
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final n()Landroidx/datastore/preferences/protobuf/z;
    .locals 0

    .line 1
    iget-object p0, p0, Lp6/g;->strings_:Landroidx/datastore/preferences/protobuf/z;

    .line 2
    .line 3
    return-object p0
.end method
