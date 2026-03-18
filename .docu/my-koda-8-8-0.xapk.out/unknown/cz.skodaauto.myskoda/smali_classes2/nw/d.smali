.class public final synthetic Lnw/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/q;


# instance fields
.field public final synthetic d:Lc1/h2;


# direct methods
.method public synthetic constructor <init>(Lnw/e;ILc1/h2;Lnw/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lnw/d;->d:Lc1/h2;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lmw/i;

    .line 2
    .line 3
    check-cast p2, Ljava/lang/Float;

    .line 4
    .line 5
    invoke-virtual {p2}, Ljava/lang/Float;->floatValue()F

    .line 6
    .line 7
    .line 8
    check-cast p3, Ljava/lang/Float;

    .line 9
    .line 10
    invoke-virtual {p3}, Ljava/lang/Float;->floatValue()F

    .line 11
    .line 12
    .line 13
    check-cast p4, Ljava/lang/Float;

    .line 14
    .line 15
    check-cast p5, Ljava/lang/Float;

    .line 16
    .line 17
    const-string p2, "chartEntry"

    .line 18
    .line 19
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    iget-wide p1, p1, Lmw/i;->a:D

    .line 23
    .line 24
    iget-object p0, p0, Lnw/d;->d:Lc1/h2;

    .line 25
    .line 26
    iget-object p3, p0, Lc1/h2;->b:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p3, Lkw/g;

    .line 29
    .line 30
    iget-object p0, p0, Lc1/h2;->e:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p0, Lkw/i;

    .line 33
    .line 34
    invoke-interface {p3}, Lkw/g;->j()Lmw/b;

    .line 35
    .line 36
    .line 37
    move-result-object p4

    .line 38
    invoke-interface {p4}, Lmw/b;->c()D

    .line 39
    .line 40
    .line 41
    move-result-wide p4

    .line 42
    cmpg-double p4, p1, p4

    .line 43
    .line 44
    if-nez p4, :cond_0

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_0
    invoke-interface {p3}, Lkw/g;->j()Lmw/b;

    .line 48
    .line 49
    .line 50
    move-result-object p4

    .line 51
    invoke-interface {p4}, Lmw/b;->a()D

    .line 52
    .line 53
    .line 54
    move-result-wide p4

    .line 55
    cmpg-double p4, p1, p4

    .line 56
    .line 57
    if-nez p4, :cond_2

    .line 58
    .line 59
    :goto_0
    invoke-interface {p3}, Lkw/g;->j()Lmw/b;

    .line 60
    .line 61
    .line 62
    move-result-object p4

    .line 63
    invoke-interface {p4}, Lmw/b;->c()D

    .line 64
    .line 65
    .line 66
    move-result-wide p4

    .line 67
    cmpg-double p4, p1, p4

    .line 68
    .line 69
    if-nez p4, :cond_1

    .line 70
    .line 71
    invoke-virtual {p0}, Lkw/i;->d()F

    .line 72
    .line 73
    .line 74
    move-result p4

    .line 75
    const/4 p5, 0x0

    .line 76
    cmpl-float p4, p4, p5

    .line 77
    .line 78
    if-gtz p4, :cond_2

    .line 79
    .line 80
    :cond_1
    invoke-interface {p3}, Lkw/g;->j()Lmw/b;

    .line 81
    .line 82
    .line 83
    move-result-object p3

    .line 84
    invoke-interface {p3}, Lmw/b;->a()D

    .line 85
    .line 86
    .line 87
    move-result-wide p3

    .line 88
    cmpg-double p1, p1, p3

    .line 89
    .line 90
    if-nez p1, :cond_2

    .line 91
    .line 92
    iget p0, p0, Lkw/i;->c:F

    .line 93
    .line 94
    :cond_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 95
    .line 96
    return-object p0
.end method
