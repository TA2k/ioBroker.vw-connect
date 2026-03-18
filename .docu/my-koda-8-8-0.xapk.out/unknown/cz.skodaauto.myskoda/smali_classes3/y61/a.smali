.class public abstract Ly61/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ll2/e0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lxf/b;

    .line 2
    .line 3
    const/16 v1, 0x13

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lxf/b;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Ll2/e0;

    .line 9
    .line 10
    invoke-direct {v1, v0}, Ll2/e0;-><init>(Lay0/a;)V

    .line 11
    .line 12
    .line 13
    sput-object v1, Ly61/a;->a:Ll2/e0;

    .line 14
    .line 15
    return-void
.end method

.method public static final a(Ljava/lang/String;Ll2/o;)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "id"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lw3/q1;->a:Ll2/u2;

    .line 7
    .line 8
    check-cast p1, Ll2/t;

    .line 9
    .line 10
    invoke-virtual {p1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    check-cast v0, Ljava/lang/Boolean;

    .line 15
    .line 16
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    const/4 v1, 0x0

    .line 21
    if-eqz v0, :cond_0

    .line 22
    .line 23
    const v0, 0xca4d9f7

    .line 24
    .line 25
    .line 26
    invoke-virtual {p1, v0}, Ll2/t;->Y(I)V

    .line 27
    .line 28
    .line 29
    :goto_0
    invoke-virtual {p1, v1}, Ll2/t;->q(Z)V

    .line 30
    .line 31
    .line 32
    return-object p0

    .line 33
    :cond_0
    const v0, 0xca4de68

    .line 34
    .line 35
    .line 36
    invoke-virtual {p1, v0}, Ll2/t;->Y(I)V

    .line 37
    .line 38
    .line 39
    sget-object v0, Ly61/a;->a:Ll2/e0;

    .line 40
    .line 41
    invoke-virtual {p1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    check-cast v0, Lh70/o;

    .line 46
    .line 47
    invoke-virtual {v0, p0}, Lh70/o;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    goto :goto_0
.end method
