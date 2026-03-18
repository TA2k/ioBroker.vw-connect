.class public abstract Lvp/u3;
.super Lvp/q3;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public g:Z


# direct methods
.method public constructor <init>(Lvp/z3;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lvp/q3;-><init>(Lvp/z3;)V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lvp/q3;->f:Lvp/z3;

    .line 5
    .line 6
    iget p1, p0, Lvp/z3;->u:I

    .line 7
    .line 8
    add-int/lit8 p1, p1, 0x1

    .line 9
    .line 10
    iput p1, p0, Lvp/z3;->u:I

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final b0()V
    .locals 1

    .line 1
    iget-boolean p0, p0, Lvp/u3;->g:Z

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 7
    .line 8
    const-string v0, "Not initialized"

    .line 9
    .line 10
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0
.end method

.method public final c0()V
    .locals 3

    .line 1
    iget-boolean v0, p0, Lvp/u3;->g:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lvp/u3;->d0()V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lvp/q3;->f:Lvp/z3;

    .line 9
    .line 10
    iget v1, v0, Lvp/z3;->v:I

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    add-int/2addr v1, v2

    .line 14
    iput v1, v0, Lvp/z3;->v:I

    .line 15
    .line 16
    iput-boolean v2, p0, Lvp/u3;->g:Z

    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 20
    .line 21
    const-string v0, "Can\'t initialize twice"

    .line 22
    .line 23
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    throw p0
.end method

.method public abstract d0()V
.end method
