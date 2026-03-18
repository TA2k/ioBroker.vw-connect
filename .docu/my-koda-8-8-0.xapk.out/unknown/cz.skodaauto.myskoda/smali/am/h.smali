.class public final Lam/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/q0;


# static fields
.field public static final a:Lam/h;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lam/h;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lam/h;->a:Lam/h;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final b(Lt3/s0;Ljava/util/List;J)Lt3/r0;
    .locals 0

    .line 1
    invoke-static {p3, p4}, Lt4/a;->j(J)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    invoke-static {p3, p4}, Lt4/a;->i(J)I

    .line 6
    .line 7
    .line 8
    move-result p2

    .line 9
    new-instance p3, Ldj/a;

    .line 10
    .line 11
    const/16 p4, 0xe

    .line 12
    .line 13
    invoke-direct {p3, p4}, Ldj/a;-><init>(I)V

    .line 14
    .line 15
    .line 16
    sget-object p4, Lmx0/t;->d:Lmx0/t;

    .line 17
    .line 18
    invoke-interface {p1, p0, p2, p4, p3}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method
