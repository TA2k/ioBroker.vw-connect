.class public final Lh0/o1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh0/o2;
.implements Lh0/a1;
.implements Ll0/l;


# instance fields
.field public final d:Lh0/n1;


# direct methods
.method public constructor <init>(Lh0/n1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh0/o1;->d:Lh0/n1;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final l()I
    .locals 1

    .line 1
    sget-object v0, Lh0/z0;->C0:Lh0/g;

    .line 2
    .line 3
    invoke-interface {p0, v0}, Lh0/t1;->f(Lh0/g;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Integer;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final p()Lh0/q0;
    .locals 0

    .line 1
    iget-object p0, p0, Lh0/o1;->d:Lh0/n1;

    .line 2
    .line 3
    return-object p0
.end method
