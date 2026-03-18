.class public final Llb0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lyb0/l;


# direct methods
.method public constructor <init>(Lyb0/l;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Llb0/g;->a:Lyb0/l;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    new-instance v0, Lyb0/i;

    .line 2
    .line 3
    sget-object v1, Lzb0/d;->e:Lzb0/d;

    .line 4
    .line 5
    const/4 v4, 0x0

    .line 6
    const/16 v5, 0x3c

    .line 7
    .line 8
    const-string v2, "air-conditioning"

    .line 9
    .line 10
    const/4 v3, 0x0

    .line 11
    invoke-direct/range {v0 .. v5}, Lyb0/i;-><init>(Lzb0/d;Ljava/lang/String;Ljava/util/Set;Lyb0/h;I)V

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, Llb0/g;->a:Lyb0/l;

    .line 15
    .line 16
    invoke-virtual {p0, v0}, Lyb0/l;->a(Lyb0/i;)Lzy0/j;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    new-instance v0, Lal0/j0;

    .line 21
    .line 22
    const/4 v1, 0x5

    .line 23
    invoke-direct {v0, p0, v1}, Lal0/j0;-><init>(Lzy0/j;I)V

    .line 24
    .line 25
    .line 26
    return-object v0
.end method
