.class public abstract Lgy0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Iterable;
.implements Lby0/a;


# instance fields
.field public final d:C

.field public final e:C

.field public final f:I


# direct methods
.method public constructor <init>(CC)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-char p1, p0, Lgy0/a;->d:C

    .line 5
    .line 6
    const/4 v0, 0x1

    .line 7
    invoke-static {p1, p2, v0}, Llp/o0;->b(III)I

    .line 8
    .line 9
    .line 10
    move-result p1

    .line 11
    int-to-char p1, p1

    .line 12
    iput-char p1, p0, Lgy0/a;->e:C

    .line 13
    .line 14
    iput v0, p0, Lgy0/a;->f:I

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final iterator()Ljava/util/Iterator;
    .locals 3

    .line 1
    new-instance v0, Lgy0/b;

    .line 2
    .line 3
    iget-char v1, p0, Lgy0/a;->e:C

    .line 4
    .line 5
    iget v2, p0, Lgy0/a;->f:I

    .line 6
    .line 7
    iget-char p0, p0, Lgy0/a;->d:C

    .line 8
    .line 9
    invoke-direct {v0, p0, v1, v2}, Lgy0/b;-><init>(CCI)V

    .line 10
    .line 11
    .line 12
    return-object v0
.end method
