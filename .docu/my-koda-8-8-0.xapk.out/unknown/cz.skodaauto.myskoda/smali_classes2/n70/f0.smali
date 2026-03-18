.class public final synthetic Ln70/f0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:Lm70/b1;

.field public final synthetic e:Z


# direct methods
.method public synthetic constructor <init>(Lm70/b1;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ln70/f0;->d:Lm70/b1;

    .line 5
    .line 6
    iput-boolean p2, p0, Ln70/f0;->e:Z

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p1, Landroidx/compose/foundation/lazy/a;

    .line 2
    .line 3
    check-cast p2, Ljava/lang/Integer;

    .line 4
    .line 5
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    check-cast p3, Ll2/o;

    .line 9
    .line 10
    check-cast p4, Ljava/lang/Integer;

    .line 11
    .line 12
    invoke-virtual {p4}, Ljava/lang/Integer;->intValue()I

    .line 13
    .line 14
    .line 15
    move-result p2

    .line 16
    const-string p4, "$this$stickyHeader"

    .line 17
    .line 18
    invoke-static {p1, p4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    and-int/lit16 p1, p2, 0x81

    .line 22
    .line 23
    const/16 p4, 0x80

    .line 24
    .line 25
    const/4 v0, 0x1

    .line 26
    const/4 v1, 0x0

    .line 27
    if-eq p1, p4, :cond_0

    .line 28
    .line 29
    move p1, v0

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    move p1, v1

    .line 32
    :goto_0
    and-int/2addr p2, v0

    .line 33
    check-cast p3, Ll2/t;

    .line 34
    .line 35
    invoke-virtual {p3, p2, p1}, Ll2/t;->O(IZ)Z

    .line 36
    .line 37
    .line 38
    move-result p1

    .line 39
    if-eqz p1, :cond_2

    .line 40
    .line 41
    iget-object p1, p0, Ln70/f0;->d:Lm70/b1;

    .line 42
    .line 43
    iget-object p1, p1, Lm70/b1;->a:Ljava/lang/String;

    .line 44
    .line 45
    invoke-static {p1, p3, v1}, Ln70/a;->J(Ljava/lang/String;Ll2/o;I)V

    .line 46
    .line 47
    .line 48
    iget-boolean p0, p0, Ln70/f0;->e:Z

    .line 49
    .line 50
    if-eqz p0, :cond_1

    .line 51
    .line 52
    const p0, -0x13f6de0a

    .line 53
    .line 54
    .line 55
    invoke-virtual {p3, p0}, Ll2/t;->Y(I)V

    .line 56
    .line 57
    .line 58
    sget-object p0, Lj91/a;->a:Ll2/u2;

    .line 59
    .line 60
    invoke-virtual {p3, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    check-cast p0, Lj91/c;

    .line 65
    .line 66
    iget p0, p0, Lj91/c;->c:F

    .line 67
    .line 68
    sget-object p1, Lx2/p;->b:Lx2/p;

    .line 69
    .line 70
    invoke-static {p1, p0, p3, v1}, Lvj/b;->z(Lx2/p;FLl2/t;Z)V

    .line 71
    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_1
    const p0, -0x14d2d0b2

    .line 75
    .line 76
    .line 77
    invoke-virtual {p3, p0}, Ll2/t;->Y(I)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {p3, v1}, Ll2/t;->q(Z)V

    .line 81
    .line 82
    .line 83
    goto :goto_1

    .line 84
    :cond_2
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 85
    .line 86
    .line 87
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 88
    .line 89
    return-object p0
.end method
