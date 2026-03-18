.class public final Lwz0/i;
.super Lb6/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final f:Z


# direct methods
.method public constructor <init>(Lb11/a;Z)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lb6/f;-><init>(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    iput-boolean p2, p0, Lwz0/i;->f:Z

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final v(Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "value"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-boolean v0, p0, Lwz0/i;->f:Z

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    invoke-super {p0, p1}, Lb6/f;->v(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    invoke-virtual {p0, p1}, Lb6/f;->t(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method
