.class public final Lci0/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lkf0/r;

.field public final b:Lai0/a;

.field public final c:Lci0/d;


# direct methods
.method public constructor <init>(Lkf0/r;Lai0/a;Lci0/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lci0/j;->a:Lkf0/r;

    .line 5
    .line 6
    iput-object p2, p0, Lci0/j;->b:Lai0/a;

    .line 7
    .line 8
    iput-object p3, p0, Lci0/j;->c:Lci0/d;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lci0/i;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lci0/j;->b(Lci0/i;)Lyy0/i;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lci0/i;)Lyy0/i;
    .locals 9

    .line 1
    iget-object v0, p1, Lci0/i;->b:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v1, p0, Lci0/j;->a:Lkf0/r;

    .line 4
    .line 5
    invoke-virtual {v1, v0}, Lkf0/r;->a(Ljava/lang/String;)Ljava/lang/Boolean;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-nez v1, :cond_0

    .line 14
    .line 15
    new-instance v2, Lne0/c;

    .line 16
    .line 17
    new-instance v3, Lb0/l;

    .line 18
    .line 19
    const-string p0, "Vehicle name "

    .line 20
    .line 21
    const-string p1, " is invalid"

    .line 22
    .line 23
    invoke-static {p0, v0, p1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    invoke-direct {v3, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    const/4 v6, 0x0

    .line 31
    const/16 v7, 0x1e

    .line 32
    .line 33
    const/4 v4, 0x0

    .line 34
    const/4 v5, 0x0

    .line 35
    invoke-direct/range {v2 .. v7}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 36
    .line 37
    .line 38
    new-instance p0, Lyy0/m;

    .line 39
    .line 40
    const/4 p1, 0x0

    .line 41
    invoke-direct {p0, v2, p1}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 42
    .line 43
    .line 44
    return-object p0

    .line 45
    :cond_0
    iget-object v6, p1, Lci0/i;->a:Ljava/lang/String;

    .line 46
    .line 47
    new-instance v7, Llf0/f;

    .line 48
    .line 49
    invoke-direct {v7, v0}, Llf0/f;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    iget-object v5, p0, Lci0/j;->b:Lai0/a;

    .line 53
    .line 54
    iget-object p1, v5, Lai0/a;->a:Lxl0/f;

    .line 55
    .line 56
    new-instance v3, La30/b;

    .line 57
    .line 58
    const/4 v4, 0x1

    .line 59
    const/4 v8, 0x0

    .line 60
    invoke-direct/range {v3 .. v8}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {p1, v3}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    new-instance v0, Lc80/l;

    .line 68
    .line 69
    const/16 v1, 0xa

    .line 70
    .line 71
    invoke-direct {v0, p0, v8, v1}, Lc80/l;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 72
    .line 73
    .line 74
    new-instance p0, Lne0/n;

    .line 75
    .line 76
    const/4 v1, 0x5

    .line 77
    invoke-direct {p0, p1, v0, v1}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 78
    .line 79
    .line 80
    return-object p0
.end method
