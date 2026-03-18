.class public final synthetic La8/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lw7/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I


# direct methods
.method public synthetic constructor <init>(II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, La8/v;->d:I

    .line 5
    .line 6
    iput p2, p0, La8/v;->e:I

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)V
    .locals 1

    .line 1
    iget v0, p0, La8/v;->e:I

    .line 2
    .line 3
    check-cast p1, Lt7/j0;

    .line 4
    .line 5
    iget p0, p0, La8/v;->d:I

    .line 6
    .line 7
    invoke-interface {p1, p0, v0}, Lt7/j0;->u(II)V

    .line 8
    .line 9
    .line 10
    return-void
.end method
