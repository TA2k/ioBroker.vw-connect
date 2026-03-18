.class public final Lw3/z1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/p1;


# instance fields
.field public final d:I

.field public final e:Ljava/util/List;

.field public f:Ljava/lang/Float;

.field public g:Ljava/lang/Float;

.field public h:Ld4/j;

.field public i:Ld4/j;


# direct methods
.method public constructor <init>(Ljava/util/ArrayList;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p2, p0, Lw3/z1;->d:I

    .line 5
    .line 6
    iput-object p1, p0, Lw3/z1;->e:Ljava/util/List;

    .line 7
    .line 8
    const/4 p1, 0x0

    .line 9
    iput-object p1, p0, Lw3/z1;->f:Ljava/lang/Float;

    .line 10
    .line 11
    iput-object p1, p0, Lw3/z1;->g:Ljava/lang/Float;

    .line 12
    .line 13
    iput-object p1, p0, Lw3/z1;->h:Ld4/j;

    .line 14
    .line 15
    iput-object p1, p0, Lw3/z1;->i:Ld4/j;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final e0()Z
    .locals 1

    .line 1
    iget-object v0, p0, Lw3/z1;->e:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {v0, p0}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
