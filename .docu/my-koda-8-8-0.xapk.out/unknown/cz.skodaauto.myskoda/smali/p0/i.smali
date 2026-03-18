.class public final synthetic Lp0/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:Lp0/k;

.field public final synthetic e:I

.field public final synthetic f:I


# direct methods
.method public synthetic constructor <init>(Lp0/k;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lp0/i;->d:Lp0/k;

    .line 5
    .line 6
    iput p2, p0, Lp0/i;->e:I

    .line 7
    .line 8
    iput p3, p0, Lp0/i;->f:I

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 4

    .line 1
    iget-object v0, p0, Lp0/i;->d:Lp0/k;

    .line 2
    .line 3
    iget v1, v0, Lp0/k;->i:I

    .line 4
    .line 5
    iget v2, p0, Lp0/i;->e:I

    .line 6
    .line 7
    const/4 v3, 0x1

    .line 8
    if-eq v1, v2, :cond_0

    .line 9
    .line 10
    iput v2, v0, Lp0/k;->i:I

    .line 11
    .line 12
    move v1, v3

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 v1, 0x0

    .line 15
    :goto_0
    iget v2, v0, Lp0/k;->h:I

    .line 16
    .line 17
    iget p0, p0, Lp0/i;->f:I

    .line 18
    .line 19
    if-eq v2, p0, :cond_1

    .line 20
    .line 21
    iput p0, v0, Lp0/k;->h:I

    .line 22
    .line 23
    goto :goto_1

    .line 24
    :cond_1
    move v3, v1

    .line 25
    :goto_1
    if-eqz v3, :cond_2

    .line 26
    .line 27
    invoke-virtual {v0}, Lp0/k;->e()V

    .line 28
    .line 29
    .line 30
    :cond_2
    return-void
.end method
