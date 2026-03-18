.class public final Lnn/k;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p1, Lu2/b;

    .line 2
    .line 3
    check-cast p2, Lnn/t;

    .line 4
    .line 5
    const-string p0, "$this$mapSaver"

    .line 6
    .line 7
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string p0, "it"

    .line 11
    .line 12
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    new-instance p0, Landroid/os/Bundle;

    .line 16
    .line 17
    invoke-direct {p0}, Landroid/os/Bundle;-><init>()V

    .line 18
    .line 19
    .line 20
    iget-object p1, p2, Lnn/t;->h:Ll2/j1;

    .line 21
    .line 22
    invoke-virtual {p1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    check-cast p1, Landroid/webkit/WebView;

    .line 27
    .line 28
    if-eqz p1, :cond_0

    .line 29
    .line 30
    invoke-virtual {p1, p0}, Landroid/webkit/WebView;->saveState(Landroid/os/Bundle;)Landroid/webkit/WebBackForwardList;

    .line 31
    .line 32
    .line 33
    :cond_0
    iget-object p1, p2, Lnn/t;->d:Ll2/j1;

    .line 34
    .line 35
    invoke-virtual {p1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    check-cast p1, Ljava/lang/String;

    .line 40
    .line 41
    new-instance v0, Llx0/l;

    .line 42
    .line 43
    const-string v1, "pagetitle"

    .line 44
    .line 45
    invoke-direct {v0, v1, p1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    iget-object p1, p2, Lnn/t;->a:Ll2/j1;

    .line 49
    .line 50
    invoke-virtual {p1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    check-cast p1, Ljava/lang/String;

    .line 55
    .line 56
    new-instance p2, Llx0/l;

    .line 57
    .line 58
    const-string v1, "lastloaded"

    .line 59
    .line 60
    invoke-direct {p2, v1, p1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    new-instance p1, Llx0/l;

    .line 64
    .line 65
    const-string v1, "bundle"

    .line 66
    .line 67
    invoke-direct {p1, v1, p0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    filled-new-array {v0, p2, p1}, [Llx0/l;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    invoke-static {p0}, Lmx0/x;->m([Llx0/l;)Ljava/util/Map;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    return-object p0
.end method
