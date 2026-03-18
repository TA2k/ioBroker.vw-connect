.class public final Lc1/l0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:I

.field public final b:Landroidx/collection/b0;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/16 v0, 0x12c

    .line 5
    .line 6
    iput v0, p0, Lc1/l0;->a:I

    .line 7
    .line 8
    sget-object v0, Landroidx/collection/q;->a:Landroidx/collection/b0;

    .line 9
    .line 10
    new-instance v0, Landroidx/collection/b0;

    .line 11
    .line 12
    invoke-direct {v0}, Landroidx/collection/b0;-><init>()V

    .line 13
    .line 14
    .line 15
    iput-object v0, p0, Lc1/l0;->b:Landroidx/collection/b0;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final a(ILjava/lang/Float;)Lc1/k0;
    .locals 2

    .line 1
    new-instance v0, Lc1/k0;

    .line 2
    .line 3
    sget-object v1, Lc1/z;->d:Lc1/y;

    .line 4
    .line 5
    invoke-direct {v0, p2, v1}, Lc1/k0;-><init>(Ljava/lang/Float;Lc1/w;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lc1/l0;->b:Landroidx/collection/b0;

    .line 9
    .line 10
    invoke-virtual {p0, p1, v0}, Landroidx/collection/b0;->h(ILjava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method
