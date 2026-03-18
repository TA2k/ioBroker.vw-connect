.class public final Lgd0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lid0/a;


# instance fields
.field public final a:Lrh0/f;

.field public final b:Llx0/q;


# direct methods
.method public constructor <init>(Lrh0/f;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lgd0/d;->a:Lrh0/f;

    .line 5
    .line 6
    new-instance p1, Lf2/h0;

    .line 7
    .line 8
    const/16 v0, 0x18

    .line 9
    .line 10
    invoke-direct {p1, v0}, Lf2/h0;-><init>(I)V

    .line 11
    .line 12
    .line 13
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    iput-object p1, p0, Lgd0/d;->b:Llx0/q;

    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final a(Lrx0/c;)Ljava/io/Serializable;
    .locals 6

    .line 1
    instance-of v0, p1, Lgd0/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lgd0/c;

    .line 7
    .line 8
    iget v1, v0, Lgd0/c;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lgd0/c;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lgd0/c;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lgd0/c;-><init>(Lgd0/d;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lgd0/c;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lgd0/c;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    sget-object p1, Lqh0/a;->g:Lqh0/a;

    .line 52
    .line 53
    iput v3, v0, Lgd0/c;->f:I

    .line 54
    .line 55
    iget-object v2, p0, Lgd0/d;->a:Lrh0/f;

    .line 56
    .line 57
    invoke-virtual {v2, p1, v0}, Lrh0/f;->d(Lqh0/a;Lrx0/c;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    if-ne p1, v1, :cond_3

    .line 62
    .line 63
    return-object v1

    .line 64
    :cond_3
    :goto_1
    check-cast p1, Ljava/lang/String;

    .line 65
    .line 66
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 67
    .line 68
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 69
    .line 70
    .line 71
    const/4 v1, 0x0

    .line 72
    :try_start_0
    new-instance v2, Lorg/json/JSONObject;

    .line 73
    .line 74
    invoke-direct {v2, p1}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {v2}, Lorg/json/JSONObject;->keys()Ljava/util/Iterator;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    const-string v3, "keys(...)"

    .line 82
    .line 83
    invoke-static {p1, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    :goto_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 87
    .line 88
    .line 89
    move-result v3

    .line 90
    if-eqz v3, :cond_4

    .line 91
    .line 92
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v3

    .line 96
    check-cast v3, Ljava/lang/String;

    .line 97
    .line 98
    invoke-virtual {v2, v3}, Lorg/json/JSONObject;->getJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    .line 99
    .line 100
    .line 101
    move-result-object v4

    .line 102
    invoke-virtual {v4}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object v4

    .line 106
    const-string v5, "toString(...)"

    .line 107
    .line 108
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {p0, v4}, Lgd0/d;->b(Ljava/lang/String;)Lcz/skodaauto/myskoda/library/callservicesdata/data/CallServicesDataDto;

    .line 112
    .line 113
    .line 114
    move-result-object v4

    .line 115
    invoke-static {v4}, Lcz/skodaauto/myskoda/library/callservicesdata/data/a;->a(Lcz/skodaauto/myskoda/library/callservicesdata/data/CallServicesDataDto;)Ljd0/d;

    .line 116
    .line 117
    .line 118
    move-result-object v4

    .line 119
    invoke-interface {v0, v3, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 120
    .line 121
    .line 122
    goto :goto_2

    .line 123
    :catch_0
    move-exception p1

    .line 124
    goto :goto_3

    .line 125
    :catch_1
    move-exception p1

    .line 126
    goto :goto_4

    .line 127
    :goto_3
    new-instance v2, Lgd0/b;

    .line 128
    .line 129
    const/4 v3, 0x0

    .line 130
    invoke-direct {v2, v3, p1}, Lgd0/b;-><init>(ILjava/lang/IllegalArgumentException;)V

    .line 131
    .line 132
    .line 133
    invoke-static {v1, p0, v2}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 134
    .line 135
    .line 136
    goto :goto_5

    .line 137
    :goto_4
    new-instance v2, Lgd0/a;

    .line 138
    .line 139
    const/4 v3, 0x0

    .line 140
    invoke-direct {v2, p1, v3}, Lgd0/a;-><init>(Lorg/json/JSONException;I)V

    .line 141
    .line 142
    .line 143
    invoke-static {v1, p0, v2}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 144
    .line 145
    .line 146
    :cond_4
    :goto_5
    return-object v0
.end method

.method public final b(Ljava/lang/String;)Lcz/skodaauto/myskoda/library/callservicesdata/data/CallServicesDataDto;
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    new-array v0, v0, [Ljava/lang/reflect/Type;

    .line 3
    .line 4
    const/4 v1, 0x0

    .line 5
    const-class v2, Lcz/skodaauto/myskoda/library/callservicesdata/data/CallServicesDataDto;

    .line 6
    .line 7
    aput-object v2, v0, v1

    .line 8
    .line 9
    invoke-static {v2, v0}, Lcom/squareup/moshi/Types;->d(Ljava/lang/Class;[Ljava/lang/reflect/Type;)Lcom/squareup/moshi/internal/Util$ParameterizedTypeImpl;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iget-object p0, p0, Lgd0/d;->b:Llx0/q;

    .line 14
    .line 15
    invoke-virtual {p0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p0, Lcom/squareup/moshi/Moshi;

    .line 20
    .line 21
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    sget-object v1, Lax/b;->a:Ljava/util/Set;

    .line 25
    .line 26
    const/4 v2, 0x0

    .line 27
    invoke-virtual {p0, v0, v1, v2}, Lcom/squareup/moshi/Moshi;->a(Ljava/lang/reflect/Type;Ljava/util/Set;Ljava/lang/String;)Lcom/squareup/moshi/JsonAdapter;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-virtual {p0, p1}, Lcom/squareup/moshi/JsonAdapter;->b(Ljava/lang/String;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    check-cast p0, Lcz/skodaauto/myskoda/library/callservicesdata/data/CallServicesDataDto;

    .line 36
    .line 37
    if-eqz p0, :cond_0

    .line 38
    .line 39
    return-object p0

    .line 40
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 41
    .line 42
    const-string v0, "Unsupported call services data format: "

    .line 43
    .line 44
    invoke-virtual {v0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0
.end method
