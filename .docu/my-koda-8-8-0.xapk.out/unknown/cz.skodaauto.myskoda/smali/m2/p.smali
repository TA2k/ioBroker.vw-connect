.class public final Lm2/p;
.super Lm2/j0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final c:Lm2/p;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lm2/p;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    invoke-direct {v0, v1, v2, v2}, Lm2/j0;-><init>(III)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lm2/p;->c:Lm2/p;

    .line 9
    .line 10
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
    check-cast p0, Ll2/a;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    invoke-virtual {p3, p0}, Ll2/i2;->c(Ll2/a;)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    invoke-virtual {p3, p0}, Ll2/i2;->l(I)V

    .line 16
    .line 17
    .line 18
    return-void
.end method
