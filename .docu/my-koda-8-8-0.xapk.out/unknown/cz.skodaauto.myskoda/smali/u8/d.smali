.class public final Lu8/d;
.super Lap0/o;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final f:Lw7/p;

.field public final g:Lw7/p;

.field public h:I

.field public i:Z

.field public j:Z

.field public k:I


# direct methods
.method public constructor <init>(Lo8/i0;)V
    .locals 1

    .line 1
    const/16 v0, 0x8

    .line 2
    .line 3
    invoke-direct {p0, p1, v0}, Lap0/o;-><init>(Ljava/lang/Object;I)V

    .line 4
    .line 5
    .line 6
    new-instance p1, Lw7/p;

    .line 7
    .line 8
    sget-object v0, Lx7/n;->a:[B

    .line 9
    .line 10
    invoke-direct {p1, v0}, Lw7/p;-><init>([B)V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lu8/d;->f:Lw7/p;

    .line 14
    .line 15
    new-instance p1, Lw7/p;

    .line 16
    .line 17
    const/4 v0, 0x4

    .line 18
    invoke-direct {p1, v0}, Lw7/p;-><init>(I)V

    .line 19
    .line 20
    .line 21
    iput-object p1, p0, Lu8/d;->g:Lw7/p;

    .line 22
    .line 23
    return-void
.end method
