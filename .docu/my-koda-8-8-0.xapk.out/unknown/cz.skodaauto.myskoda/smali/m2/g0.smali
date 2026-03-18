.class public final Lm2/g0;
.super Lm2/j0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final c:Lm2/g0;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lm2/g0;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    const/4 v2, 0x1

    .line 5
    const/4 v3, 0x0

    .line 6
    invoke-direct {v0, v3, v1, v2}, Lm2/j0;-><init>(III)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lm2/g0;->c:Lm2/g0;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final a(Landroidx/collection/h;Ll2/c;Ll2/i2;Ljp/uf;Lm2/k0;)V
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    invoke-virtual {p1, p0}, Landroidx/collection/h;->g(I)Ljava/lang/Object;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    const/4 p3, 0x1

    .line 7
    invoke-virtual {p1, p3}, Landroidx/collection/h;->g(I)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    check-cast p1, Lay0/n;

    .line 12
    .line 13
    invoke-interface {p2, p0, p1}, Ll2/c;->d(Ljava/lang/Object;Lay0/n;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method
