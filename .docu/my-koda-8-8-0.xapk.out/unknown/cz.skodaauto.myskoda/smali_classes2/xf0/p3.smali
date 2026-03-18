.class public final synthetic Lxf0/p3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:Lvy0/b0;

.field public final synthetic e:Lp1/b;

.field public final synthetic f:I

.field public final synthetic g:Lay0/n;

.field public final synthetic h:Lxf0/o3;


# direct methods
.method public synthetic constructor <init>(Lvy0/b0;Lp1/b;ILay0/n;Lxf0/o3;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lxf0/p3;->d:Lvy0/b0;

    .line 5
    .line 6
    iput-object p2, p0, Lxf0/p3;->e:Lp1/b;

    .line 7
    .line 8
    iput p3, p0, Lxf0/p3;->f:I

    .line 9
    .line 10
    iput-object p4, p0, Lxf0/p3;->g:Lay0/n;

    .line 11
    .line 12
    iput-object p5, p0, Lxf0/p3;->h:Lxf0/o3;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 7

    .line 1
    new-instance v0, Lci0/a;

    .line 2
    .line 3
    const/4 v5, 0x0

    .line 4
    const/16 v6, 0x8

    .line 5
    .line 6
    iget-object v1, p0, Lxf0/p3;->e:Lp1/b;

    .line 7
    .line 8
    iget v2, p0, Lxf0/p3;->f:I

    .line 9
    .line 10
    iget-object v3, p0, Lxf0/p3;->g:Lay0/n;

    .line 11
    .line 12
    iget-object v4, p0, Lxf0/p3;->h:Lxf0/o3;

    .line 13
    .line 14
    invoke-direct/range {v0 .. v6}, Lci0/a;-><init>(Ljava/lang/Object;ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 15
    .line 16
    .line 17
    const/4 v1, 0x3

    .line 18
    iget-object p0, p0, Lxf0/p3;->d:Lvy0/b0;

    .line 19
    .line 20
    const/4 v2, 0x0

    .line 21
    invoke-static {p0, v2, v2, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 22
    .line 23
    .line 24
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 25
    .line 26
    return-object p0
.end method
