.class public final Ll2/s2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Iterable;
.implements Lby0/a;


# instance fields
.field public final d:Ll2/f2;

.field public final e:I

.field public final f:Ll2/b;


# direct methods
.method public constructor <init>(Ll2/f2;ILl2/p0;Ll2/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll2/s2;->d:Ll2/f2;

    .line 5
    .line 6
    iput p2, p0, Ll2/s2;->e:I

    .line 7
    .line 8
    iput-object p4, p0, Ll2/s2;->f:Ll2/b;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final iterator()Ljava/util/Iterator;
    .locals 4

    .line 1
    new-instance v0, Ll2/o0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    iget-object v2, p0, Ll2/s2;->f:Ll2/b;

    .line 5
    .line 6
    iget-object v3, p0, Ll2/s2;->d:Ll2/f2;

    .line 7
    .line 8
    iget p0, p0, Ll2/s2;->e:I

    .line 9
    .line 10
    invoke-direct {v0, v3, p0, v1, v2}, Ll2/o0;-><init>(Ll2/f2;ILl2/p0;Ll2/b;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method
