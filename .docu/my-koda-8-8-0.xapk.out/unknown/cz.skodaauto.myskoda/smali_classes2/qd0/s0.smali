.class public final Lqd0/s0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lqd0/z;


# direct methods
.method public constructor <init>(Lqd0/z;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lqd0/s0;->a:Lqd0/z;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lne0/s;

    .line 5
    .line 6
    iget-object p0, p0, Lqd0/s0;->a:Lqd0/z;

    .line 7
    .line 8
    check-cast p0, Lod0/v;

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    invoke-virtual {p0, v1}, Lod0/v;->b(Lne0/s;)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method
