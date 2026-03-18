.class final Lcom/google/gson/internal/bind/MapTypeAdapterFactory$Adapter;
.super Lcom/google/gson/y;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/gson/internal/bind/MapTypeAdapterFactory;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x11
    name = "Adapter"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<K:",
        "Ljava/lang/Object;",
        "V:",
        "Ljava/lang/Object;",
        ">",
        "Lcom/google/gson/y;"
    }
.end annotation


# instance fields
.field public final a:Lcom/google/gson/y;

.field public final b:Lcom/google/gson/y;

.field public final c:Lcom/google/gson/internal/m;


# direct methods
.method public constructor <init>(Lcom/google/gson/internal/bind/MapTypeAdapterFactory;Lcom/google/gson/y;Lcom/google/gson/y;Lcom/google/gson/internal/m;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lcom/google/gson/internal/bind/MapTypeAdapterFactory$Adapter;->a:Lcom/google/gson/y;

    .line 5
    .line 6
    iput-object p3, p0, Lcom/google/gson/internal/bind/MapTypeAdapterFactory$Adapter;->b:Lcom/google/gson/y;

    .line 7
    .line 8
    iput-object p4, p0, Lcom/google/gson/internal/bind/MapTypeAdapterFactory$Adapter;->c:Lcom/google/gson/internal/m;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final b(Lpu/a;)Ljava/lang/Object;
    .locals 5

    .line 1
    invoke-virtual {p1}, Lpu/a;->l0()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/16 v1, 0x9

    .line 6
    .line 7
    if-ne v0, v1, :cond_0

    .line 8
    .line 9
    invoke-virtual {p1}, Lpu/a;->W()V

    .line 10
    .line 11
    .line 12
    const/4 p0, 0x0

    .line 13
    return-object p0

    .line 14
    :cond_0
    iget-object v2, p0, Lcom/google/gson/internal/bind/MapTypeAdapterFactory$Adapter;->c:Lcom/google/gson/internal/m;

    .line 15
    .line 16
    invoke-interface {v2}, Lcom/google/gson/internal/m;->a()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    check-cast v2, Ljava/util/Map;

    .line 21
    .line 22
    const/4 v3, 0x1

    .line 23
    const-string v4, "duplicate key: "

    .line 24
    .line 25
    if-ne v0, v3, :cond_3

    .line 26
    .line 27
    invoke-virtual {p1}, Lpu/a;->a()V

    .line 28
    .line 29
    .line 30
    :goto_0
    invoke-virtual {p1}, Lpu/a;->l()Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eqz v0, :cond_2

    .line 35
    .line 36
    invoke-virtual {p1}, Lpu/a;->a()V

    .line 37
    .line 38
    .line 39
    iget-object v0, p0, Lcom/google/gson/internal/bind/MapTypeAdapterFactory$Adapter;->a:Lcom/google/gson/y;

    .line 40
    .line 41
    check-cast v0, Lcom/google/gson/internal/bind/TypeAdapterRuntimeTypeWrapper;

    .line 42
    .line 43
    iget-object v0, v0, Lcom/google/gson/internal/bind/TypeAdapterRuntimeTypeWrapper;->b:Lcom/google/gson/y;

    .line 44
    .line 45
    invoke-virtual {v0, p1}, Lcom/google/gson/y;->b(Lpu/a;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    iget-object v1, p0, Lcom/google/gson/internal/bind/MapTypeAdapterFactory$Adapter;->b:Lcom/google/gson/y;

    .line 50
    .line 51
    check-cast v1, Lcom/google/gson/internal/bind/TypeAdapterRuntimeTypeWrapper;

    .line 52
    .line 53
    iget-object v1, v1, Lcom/google/gson/internal/bind/TypeAdapterRuntimeTypeWrapper;->b:Lcom/google/gson/y;

    .line 54
    .line 55
    invoke-virtual {v1, p1}, Lcom/google/gson/y;->b(Lpu/a;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    invoke-interface {v2, v0, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v1

    .line 63
    if-nez v1, :cond_1

    .line 64
    .line 65
    invoke-virtual {p1}, Lpu/a;->g()V

    .line 66
    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_1
    new-instance p0, Lcom/google/gson/o;

    .line 70
    .line 71
    invoke-static {v0, v4}, Lkx/a;->i(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    throw p0

    .line 79
    :cond_2
    invoke-virtual {p1}, Lpu/a;->g()V

    .line 80
    .line 81
    .line 82
    return-object v2

    .line 83
    :cond_3
    invoke-virtual {p1}, Lpu/a;->b()V

    .line 84
    .line 85
    .line 86
    :goto_1
    invoke-virtual {p1}, Lpu/a;->l()Z

    .line 87
    .line 88
    .line 89
    move-result v0

    .line 90
    if-eqz v0, :cond_9

    .line 91
    .line 92
    sget-object v0, Lst/b;->f:Lst/b;

    .line 93
    .line 94
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 95
    .line 96
    .line 97
    iget v0, p1, Lpu/a;->j:I

    .line 98
    .line 99
    if-nez v0, :cond_4

    .line 100
    .line 101
    invoke-virtual {p1}, Lpu/a;->f()I

    .line 102
    .line 103
    .line 104
    move-result v0

    .line 105
    :cond_4
    const/16 v3, 0xd

    .line 106
    .line 107
    if-ne v0, v3, :cond_5

    .line 108
    .line 109
    iput v1, p1, Lpu/a;->j:I

    .line 110
    .line 111
    goto :goto_2

    .line 112
    :cond_5
    const/16 v3, 0xc

    .line 113
    .line 114
    if-ne v0, v3, :cond_6

    .line 115
    .line 116
    const/16 v0, 0x8

    .line 117
    .line 118
    iput v0, p1, Lpu/a;->j:I

    .line 119
    .line 120
    goto :goto_2

    .line 121
    :cond_6
    const/16 v3, 0xe

    .line 122
    .line 123
    if-ne v0, v3, :cond_8

    .line 124
    .line 125
    const/16 v0, 0xa

    .line 126
    .line 127
    iput v0, p1, Lpu/a;->j:I

    .line 128
    .line 129
    :goto_2
    iget-object v0, p0, Lcom/google/gson/internal/bind/MapTypeAdapterFactory$Adapter;->a:Lcom/google/gson/y;

    .line 130
    .line 131
    check-cast v0, Lcom/google/gson/internal/bind/TypeAdapterRuntimeTypeWrapper;

    .line 132
    .line 133
    iget-object v0, v0, Lcom/google/gson/internal/bind/TypeAdapterRuntimeTypeWrapper;->b:Lcom/google/gson/y;

    .line 134
    .line 135
    invoke-virtual {v0, p1}, Lcom/google/gson/y;->b(Lpu/a;)Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object v0

    .line 139
    iget-object v3, p0, Lcom/google/gson/internal/bind/MapTypeAdapterFactory$Adapter;->b:Lcom/google/gson/y;

    .line 140
    .line 141
    check-cast v3, Lcom/google/gson/internal/bind/TypeAdapterRuntimeTypeWrapper;

    .line 142
    .line 143
    iget-object v3, v3, Lcom/google/gson/internal/bind/TypeAdapterRuntimeTypeWrapper;->b:Lcom/google/gson/y;

    .line 144
    .line 145
    invoke-virtual {v3, p1}, Lcom/google/gson/y;->b(Lpu/a;)Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v3

    .line 149
    invoke-interface {v2, v0, v3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object v3

    .line 153
    if-nez v3, :cond_7

    .line 154
    .line 155
    goto :goto_1

    .line 156
    :cond_7
    new-instance p0, Lcom/google/gson/o;

    .line 157
    .line 158
    invoke-static {v0, v4}, Lkx/a;->i(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;

    .line 159
    .line 160
    .line 161
    move-result-object p1

    .line 162
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 163
    .line 164
    .line 165
    throw p0

    .line 166
    :cond_8
    const-string p0, "a name"

    .line 167
    .line 168
    invoke-virtual {p1, p0}, Lpu/a;->B0(Ljava/lang/String;)Ljava/lang/IllegalStateException;

    .line 169
    .line 170
    .line 171
    move-result-object p0

    .line 172
    throw p0

    .line 173
    :cond_9
    invoke-virtual {p1}, Lpu/a;->h()V

    .line 174
    .line 175
    .line 176
    return-object v2
.end method

.method public final c(Lpu/b;Ljava/lang/Object;)V
    .locals 2

    .line 1
    check-cast p2, Ljava/util/Map;

    .line 2
    .line 3
    if-nez p2, :cond_0

    .line 4
    .line 5
    invoke-virtual {p1}, Lpu/b;->l()Lpu/b;

    .line 6
    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    invoke-virtual {p1}, Lpu/b;->d()V

    .line 10
    .line 11
    .line 12
    invoke-interface {p2}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 13
    .line 14
    .line 15
    move-result-object p2

    .line 16
    invoke-interface {p2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 17
    .line 18
    .line 19
    move-result-object p2

    .line 20
    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-eqz v0, :cond_1

    .line 25
    .line 26
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    check-cast v0, Ljava/util/Map$Entry;

    .line 31
    .line 32
    invoke-interface {v0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    invoke-static {v1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    invoke-virtual {p1, v1}, Lpu/b;->j(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    iget-object v1, p0, Lcom/google/gson/internal/bind/MapTypeAdapterFactory$Adapter;->b:Lcom/google/gson/y;

    .line 48
    .line 49
    invoke-virtual {v1, p1, v0}, Lcom/google/gson/y;->c(Lpu/b;Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_1
    invoke-virtual {p1}, Lpu/b;->h()V

    .line 54
    .line 55
    .line 56
    return-void
.end method
