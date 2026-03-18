.class public final Lh90/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:Lvy0/b0;

.field public final synthetic e:Lxf0/d2;

.field public final synthetic f:Lay0/k;

.field public final synthetic g:I


# direct methods
.method public constructor <init>(Lvy0/b0;Lxf0/d2;Lay0/k;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh90/c;->d:Lvy0/b0;

    .line 5
    .line 6
    iput-object p2, p0, Lh90/c;->e:Lxf0/d2;

    .line 7
    .line 8
    iput-object p3, p0, Lh90/c;->f:Lay0/k;

    .line 9
    .line 10
    iput p4, p0, Lh90/c;->g:I

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    new-instance v0, Lh90/b;

    .line 2
    .line 3
    iget v3, p0, Lh90/c;->g:I

    .line 4
    .line 5
    const/4 v5, 0x0

    .line 6
    iget-object v1, p0, Lh90/c;->e:Lxf0/d2;

    .line 7
    .line 8
    iget-object v2, p0, Lh90/c;->f:Lay0/k;

    .line 9
    .line 10
    const/4 v4, 0x0

    .line 11
    invoke-direct/range {v0 .. v5}, Lh90/b;-><init>(Lxf0/d2;Lay0/k;ILkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    const/4 v1, 0x3

    .line 15
    iget-object p0, p0, Lh90/c;->d:Lvy0/b0;

    .line 16
    .line 17
    invoke-static {p0, v4, v4, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 18
    .line 19
    .line 20
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 21
    .line 22
    return-object p0
.end method
