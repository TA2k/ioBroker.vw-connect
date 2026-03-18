.class public final Ll2/r1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll2/b1;
.implements Lvy0/b0;


# instance fields
.field public final synthetic d:Ll2/b1;

.field public final e:Lpx0/g;


# direct methods
.method public constructor <init>(Ll2/b1;Lpx0/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll2/r1;->d:Ll2/b1;

    .line 5
    .line 6
    iput-object p2, p0, Ll2/r1;->e:Lpx0/g;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final getCoroutineContext()Lpx0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Ll2/r1;->e:Lpx0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getValue()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Ll2/r1;->d:Ll2/b1;

    .line 2
    .line 3
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final j()Lay0/k;
    .locals 0

    .line 1
    iget-object p0, p0, Ll2/r1;->d:Ll2/b1;

    .line 2
    .line 3
    invoke-interface {p0}, Ll2/b1;->j()Lay0/k;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final setValue(Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget-object p0, p0, Ll2/r1;->d:Ll2/b1;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
