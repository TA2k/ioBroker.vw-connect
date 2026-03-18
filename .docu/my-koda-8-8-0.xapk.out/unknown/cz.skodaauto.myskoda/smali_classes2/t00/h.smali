.class public final Lt00/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lt00/k;


# direct methods
.method public constructor <init>(Lt00/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lt00/h;->a:Lt00/k;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 5

    .line 1
    check-cast p1, Ljava/util/Map;

    .line 2
    .line 3
    new-instance p2, Lne0/e;

    .line 4
    .line 5
    invoke-interface {p1}, Ljava/util/Map;->isEmpty()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, 0x0

    .line 10
    if-nez v0, :cond_3

    .line 11
    .line 12
    new-instance v0, Lu00/a;

    .line 13
    .line 14
    const-string v2, "category"

    .line 15
    .line 16
    invoke-interface {p1, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    check-cast v2, Ljava/lang/String;

    .line 21
    .line 22
    const-string v3, ""

    .line 23
    .line 24
    if-nez v2, :cond_0

    .line 25
    .line 26
    move-object v2, v3

    .line 27
    :cond_0
    const-string v4, "description"

    .line 28
    .line 29
    invoke-interface {p1, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v4

    .line 33
    check-cast v4, Ljava/lang/String;

    .line 34
    .line 35
    if-nez v4, :cond_1

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_1
    move-object v3, v4

    .line 39
    :goto_0
    const-string v4, "rating"

    .line 40
    .line 41
    invoke-interface {p1, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v4

    .line 45
    check-cast v4, Ljava/lang/String;

    .line 46
    .line 47
    if-eqz v4, :cond_2

    .line 48
    .line 49
    invoke-static {v4}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    new-instance v4, Ljava/lang/Integer;

    .line 54
    .line 55
    invoke-direct {v4, v1}, Ljava/lang/Integer;-><init>(I)V

    .line 56
    .line 57
    .line 58
    move-object v1, v4

    .line 59
    :cond_2
    const-string v4, "contact"

    .line 60
    .line 61
    invoke-interface {p1, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    check-cast p1, Ljava/lang/String;

    .line 66
    .line 67
    invoke-static {p1}, Ljava/lang/Boolean;->parseBoolean(Ljava/lang/String;)Z

    .line 68
    .line 69
    .line 70
    move-result p1

    .line 71
    invoke-direct {v0, v1, v2, v3, p1}, Lu00/a;-><init>(Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 72
    .line 73
    .line 74
    move-object v1, v0

    .line 75
    :cond_3
    iget-object p0, p0, Lt00/h;->a:Lt00/k;

    .line 76
    .line 77
    iget-object p0, p0, Lt00/k;->a:Lt00/c;

    .line 78
    .line 79
    check-cast p0, Ls00/a;

    .line 80
    .line 81
    iput-object v1, p0, Ls00/a;->a:Lu00/a;

    .line 82
    .line 83
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 84
    .line 85
    invoke-direct {p2, p0}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    return-object p2
.end method
