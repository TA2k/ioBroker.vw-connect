.class public final Lf1/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:Lay0/n;

.field public final synthetic e:Lay0/o;

.field public final synthetic f:Lay0/a;


# direct methods
.method public constructor <init>(Lay0/n;Lay0/o;Lay0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf1/d;->d:Lay0/n;

    .line 5
    .line 6
    iput-object p2, p0, Lf1/d;->e:Lay0/o;

    .line 7
    .line 8
    iput-object p3, p0, Lf1/d;->f:Lay0/a;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    move-object v1, p1

    .line 2
    check-cast v1, Lf1/c;

    .line 3
    .line 4
    check-cast p2, Ll2/o;

    .line 5
    .line 6
    check-cast p3, Ljava/lang/Number;

    .line 7
    .line 8
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    and-int/lit8 p3, p1, 0x6

    .line 13
    .line 14
    if-nez p3, :cond_1

    .line 15
    .line 16
    move-object p3, p2

    .line 17
    check-cast p3, Ll2/t;

    .line 18
    .line 19
    invoke-virtual {p3, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result p3

    .line 23
    if-eqz p3, :cond_0

    .line 24
    .line 25
    const/4 p3, 0x4

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 p3, 0x2

    .line 28
    :goto_0
    or-int/2addr p1, p3

    .line 29
    :cond_1
    and-int/lit8 p3, p1, 0x13

    .line 30
    .line 31
    const/16 v0, 0x12

    .line 32
    .line 33
    const/4 v2, 0x0

    .line 34
    if-eq p3, v0, :cond_2

    .line 35
    .line 36
    const/4 p3, 0x1

    .line 37
    goto :goto_1

    .line 38
    :cond_2
    move p3, v2

    .line 39
    :goto_1
    and-int/lit8 v0, p1, 0x1

    .line 40
    .line 41
    move-object v5, p2

    .line 42
    check-cast v5, Ll2/t;

    .line 43
    .line 44
    invoke-virtual {v5, v0, p3}, Ll2/t;->O(IZ)Z

    .line 45
    .line 46
    .line 47
    move-result p2

    .line 48
    if-eqz p2, :cond_4

    .line 49
    .line 50
    iget-object p2, p0, Lf1/d;->d:Lay0/n;

    .line 51
    .line 52
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 53
    .line 54
    .line 55
    move-result-object p3

    .line 56
    invoke-interface {p2, v5, p3}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object p2

    .line 60
    move-object v0, p2

    .line 61
    check-cast v0, Ljava/lang/String;

    .line 62
    .line 63
    invoke-static {v0}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 64
    .line 65
    .line 66
    move-result p2

    .line 67
    if-eqz p2, :cond_3

    .line 68
    .line 69
    const-string p2, "Label must not be blank"

    .line 70
    .line 71
    invoke-static {p2}, Lj1/b;->c(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    :cond_3
    shl-int/lit8 p1, p1, 0x6

    .line 75
    .line 76
    and-int/lit16 v6, p1, 0x380

    .line 77
    .line 78
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 79
    .line 80
    iget-object v3, p0, Lf1/d;->e:Lay0/o;

    .line 81
    .line 82
    iget-object v4, p0, Lf1/d;->f:Lay0/a;

    .line 83
    .line 84
    invoke-static/range {v0 .. v6}, Lf1/g;->c(Ljava/lang/String;Lf1/c;Lx2/s;Lay0/o;Lay0/a;Ll2/o;I)V

    .line 85
    .line 86
    .line 87
    goto :goto_2

    .line 88
    :cond_4
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 89
    .line 90
    .line 91
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 92
    .line 93
    return-object p0
.end method
