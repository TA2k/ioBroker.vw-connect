.class public final synthetic Lh2/r2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lay0/n;

.field public final synthetic e:J

.field public final synthetic f:J

.field public final synthetic g:F

.field public final synthetic h:Lt2/b;

.field public final synthetic i:I


# direct methods
.method public synthetic constructor <init>(Lay0/n;JJFLt2/b;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/r2;->d:Lay0/n;

    .line 5
    .line 6
    iput-wide p2, p0, Lh2/r2;->e:J

    .line 7
    .line 8
    iput-wide p4, p0, Lh2/r2;->f:J

    .line 9
    .line 10
    iput p6, p0, Lh2/r2;->g:F

    .line 11
    .line 12
    iput-object p7, p0, Lh2/r2;->h:Lt2/b;

    .line 13
    .line 14
    iput p8, p0, Lh2/r2;->i:I

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    move-object v7, p1

    .line 2
    check-cast v7, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    iget p1, p0, Lh2/r2;->i:I

    .line 10
    .line 11
    or-int/lit8 p1, p1, 0x1

    .line 12
    .line 13
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 14
    .line 15
    .line 16
    move-result v8

    .line 17
    iget-object v0, p0, Lh2/r2;->d:Lay0/n;

    .line 18
    .line 19
    iget-wide v1, p0, Lh2/r2;->e:J

    .line 20
    .line 21
    iget-wide v3, p0, Lh2/r2;->f:J

    .line 22
    .line 23
    iget v5, p0, Lh2/r2;->g:F

    .line 24
    .line 25
    iget-object v6, p0, Lh2/r2;->h:Lt2/b;

    .line 26
    .line 27
    invoke-static/range {v0 .. v8}, Lh2/m3;->d(Lay0/n;JJFLt2/b;Ll2/o;I)V

    .line 28
    .line 29
    .line 30
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 31
    .line 32
    return-object p0
.end method
