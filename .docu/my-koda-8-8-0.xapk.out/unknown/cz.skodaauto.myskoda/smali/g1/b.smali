.class public abstract Lg1/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lc1/a2;

.field public static final b:Lfw0/i0;

.field public static final c:Lc1/u;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x7

    .line 3
    const/4 v2, 0x0

    .line 4
    invoke-static {v2, v2, v0, v1}, Lc1/d;->u(IILc1/w;I)Lc1/a2;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    sput-object v0, Lg1/b;->a:Lc1/a2;

    .line 9
    .line 10
    new-instance v0, Lfw0/i0;

    .line 11
    .line 12
    const/4 v1, 0x2

    .line 13
    invoke-direct {v0, v1}, Lfw0/i0;-><init>(I)V

    .line 14
    .line 15
    .line 16
    sput-object v0, Lg1/b;->b:Lfw0/i0;

    .line 17
    .line 18
    const/4 v0, 0x3

    .line 19
    invoke-static {v0}, Lc1/d;->o(I)Lc1/u;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    sput-object v0, Lg1/b;->c:Lc1/u;

    .line 24
    .line 25
    return-void
.end method
