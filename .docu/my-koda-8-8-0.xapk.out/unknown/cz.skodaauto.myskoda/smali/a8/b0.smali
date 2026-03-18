.class public final synthetic La8/b0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lw7/j;
.implements Lzn/b;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILt7/k0;Lt7/k0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, La8/b0;->d:I

    iput-object p2, p0, La8/b0;->e:Ljava/lang/Object;

    iput-object p3, p0, La8/b0;->f:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lqn/s;Lrn/j;I)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La8/b0;->e:Ljava/lang/Object;

    iput-object p2, p0, La8/b0;->f:Ljava/lang/Object;

    iput p3, p0, La8/b0;->d:I

    return-void
.end method


# virtual methods
.method public execute()Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object v0, p0, La8/b0;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lqn/s;

    .line 4
    .line 5
    iget-object v1, p0, La8/b0;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Lrn/j;

    .line 8
    .line 9
    iget-object v0, v0, Lqn/s;->d:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v0, Lrn/i;

    .line 12
    .line 13
    iget p0, p0, La8/b0;->d:I

    .line 14
    .line 15
    add-int/lit8 p0, p0, 0x1

    .line 16
    .line 17
    const/4 v2, 0x0

    .line 18
    invoke-virtual {v0, v1, p0, v2}, Lrn/i;->z(Lrn/j;IZ)V

    .line 19
    .line 20
    .line 21
    const/4 p0, 0x0

    .line 22
    return-object p0
.end method

.method public invoke(Ljava/lang/Object;)V
    .locals 2

    .line 1
    iget-object v0, p0, La8/b0;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lt7/k0;

    .line 4
    .line 5
    iget-object v1, p0, La8/b0;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Lt7/k0;

    .line 8
    .line 9
    check-cast p1, Lt7/j0;

    .line 10
    .line 11
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    iget p0, p0, La8/b0;->d:I

    .line 15
    .line 16
    invoke-interface {p1, p0, v0, v1}, Lt7/j0;->q(ILt7/k0;Lt7/k0;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method
