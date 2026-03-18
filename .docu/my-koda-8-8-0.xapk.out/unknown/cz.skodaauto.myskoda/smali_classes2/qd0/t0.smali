.class public final Lqd0/t0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lqd0/y;


# direct methods
.method public constructor <init>(Lqd0/y;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lqd0/t0;->a:Lqd0/y;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lrd0/n;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lqd0/t0;->a:Lqd0/y;

    .line 2
    .line 3
    check-cast p0, Lod0/u;

    .line 4
    .line 5
    iget-object p0, p0, Lod0/u;->f:Lyy0/c2;

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    invoke-virtual {p0, v0, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lrd0/n;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Lqd0/t0;->a(Lrd0/n;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
