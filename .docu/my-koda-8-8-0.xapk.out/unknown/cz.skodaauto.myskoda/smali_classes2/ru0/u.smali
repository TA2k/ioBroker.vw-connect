.class public final Lru0/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lyb0/l;

.field public final b:Lpu0/b;


# direct methods
.method public constructor <init>(Lyb0/l;Lru0/d;Lpu0/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lru0/u;->a:Lyb0/l;

    .line 5
    .line 6
    iput-object p3, p0, Lru0/u;->b:Lpu0/b;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    new-instance v0, Lyb0/i;

    .line 2
    .line 3
    sget-object v1, Lzb0/d;->g:Lzb0/d;

    .line 4
    .line 5
    sget-object v2, Lyb0/d;->d:Lyb0/d;

    .line 6
    .line 7
    const/16 v5, 0xc

    .line 8
    .line 9
    const-string v2, "vehicle-connection-status"

    .line 10
    .line 11
    const/4 v3, 0x0

    .line 12
    const/4 v4, 0x0

    .line 13
    invoke-direct/range {v0 .. v5}, Lyb0/i;-><init>(Lzb0/d;Ljava/lang/String;Ljava/util/Set;Lyb0/h;I)V

    .line 14
    .line 15
    .line 16
    iget-object v1, p0, Lru0/u;->a:Lyb0/l;

    .line 17
    .line 18
    invoke-virtual {v1, v0}, Lyb0/l;->a(Lyb0/i;)Lzy0/j;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    new-instance v1, Llb0/y;

    .line 23
    .line 24
    const/16 v2, 0xa

    .line 25
    .line 26
    invoke-direct {v1, v2, v0, p0}, Llb0/y;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    return-object v1
.end method
