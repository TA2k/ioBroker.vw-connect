.class public final Lk4/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lk4/i0;
.implements Ll2/t2;


# instance fields
.field public final d:Lk4/f;


# direct methods
.method public constructor <init>(Lk4/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk4/g0;->d:Lk4/f;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final getValue()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lk4/g0;->d:Lk4/f;

    .line 2
    .line 3
    invoke-virtual {p0}, Lk4/f;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final h()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lk4/g0;->d:Lk4/f;

    .line 2
    .line 3
    iget-boolean p0, p0, Lk4/f;->j:Z

    .line 4
    .line 5
    return p0
.end method
