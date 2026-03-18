.class public abstract Lvv/q0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ll2/e0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    sget-object v0, Lvv/s;->l:Lvv/s;

    .line 2
    .line 3
    new-instance v1, Ll2/e0;

    .line 4
    .line 5
    invoke-direct {v1, v0}, Ll2/e0;-><init>(Lay0/a;)V

    .line 6
    .line 7
    .line 8
    sput-object v1, Lvv/q0;->a:Ll2/e0;

    .line 9
    .line 10
    return-void
.end method

.method public static final a(Lvv/m0;Ll2/o;)Lay0/p;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/t;

    .line 7
    .line 8
    const p0, 0x3dbfdcc6

    .line 9
    .line 10
    .line 11
    invoke-virtual {p1, p0}, Ll2/t;->Z(I)V

    .line 12
    .line 13
    .line 14
    sget-object p0, Lvv/q0;->a:Ll2/e0;

    .line 15
    .line 16
    invoke-virtual {p1, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    check-cast p0, Lvv/p0;

    .line 21
    .line 22
    iget-object p0, p0, Lvv/p0;->b:Lay0/p;

    .line 23
    .line 24
    const/4 v0, 0x0

    .line 25
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 26
    .line 27
    .line 28
    return-object p0
.end method
