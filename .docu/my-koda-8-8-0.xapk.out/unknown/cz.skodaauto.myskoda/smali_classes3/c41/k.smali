.class public final synthetic Lc41/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:Lc3/j;

.field public final synthetic e:Lay0/k;

.field public final synthetic f:Lay0/o;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:I

.field public final synthetic i:Z


# direct methods
.method public synthetic constructor <init>(Lc3/j;Lay0/k;Lay0/o;Ljava/lang/Object;IZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lc41/k;->d:Lc3/j;

    .line 5
    .line 6
    iput-object p2, p0, Lc41/k;->e:Lay0/k;

    .line 7
    .line 8
    iput-object p3, p0, Lc41/k;->f:Lay0/o;

    .line 9
    .line 10
    iput-object p4, p0, Lc41/k;->g:Ljava/lang/Object;

    .line 11
    .line 12
    iput p5, p0, Lc41/k;->h:I

    .line 13
    .line 14
    iput-boolean p6, p0, Lc41/k;->i:Z

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lc41/k;->d:Lc3/j;

    .line 2
    .line 3
    check-cast v0, Lc3/l;

    .line 4
    .line 5
    const/4 v1, 0x1

    .line 6
    invoke-virtual {v0, v1}, Lc3/l;->b(Z)V

    .line 7
    .line 8
    .line 9
    iget v0, p0, Lc41/k;->h:I

    .line 10
    .line 11
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iget-boolean v2, p0, Lc41/k;->i:Z

    .line 16
    .line 17
    xor-int/2addr v1, v2

    .line 18
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    iget-object v2, p0, Lc41/k;->f:Lay0/o;

    .line 23
    .line 24
    iget-object v3, p0, Lc41/k;->g:Ljava/lang/Object;

    .line 25
    .line 26
    invoke-interface {v2, v3, v0, v1}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    iget-object p0, p0, Lc41/k;->e:Lay0/k;

    .line 31
    .line 32
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    return-object p0
.end method
