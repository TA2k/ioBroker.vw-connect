.class public final synthetic Lh2/p6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lx2/s;

.field public final synthetic e:J

.field public final synthetic f:J

.field public final synthetic g:F

.field public final synthetic h:Lk1/q1;

.field public final synthetic i:Lt2/b;


# direct methods
.method public synthetic constructor <init>(Lx2/s;JJFLk1/q1;Lt2/b;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/p6;->d:Lx2/s;

    .line 5
    .line 6
    iput-wide p2, p0, Lh2/p6;->e:J

    .line 7
    .line 8
    iput-wide p4, p0, Lh2/p6;->f:J

    .line 9
    .line 10
    iput p6, p0, Lh2/p6;->g:F

    .line 11
    .line 12
    iput-object p7, p0, Lh2/p6;->h:Lk1/q1;

    .line 13
    .line 14
    iput-object p8, p0, Lh2/p6;->i:Lt2/b;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    move-object v8, p1

    .line 2
    check-cast v8, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    const p1, 0x30c07

    .line 10
    .line 11
    .line 12
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 13
    .line 14
    .line 15
    move-result v9

    .line 16
    iget-object v0, p0, Lh2/p6;->d:Lx2/s;

    .line 17
    .line 18
    iget-wide v1, p0, Lh2/p6;->e:J

    .line 19
    .line 20
    iget-wide v3, p0, Lh2/p6;->f:J

    .line 21
    .line 22
    iget v5, p0, Lh2/p6;->g:F

    .line 23
    .line 24
    iget-object v6, p0, Lh2/p6;->h:Lk1/q1;

    .line 25
    .line 26
    iget-object v7, p0, Lh2/p6;->i:Lt2/b;

    .line 27
    .line 28
    invoke-static/range {v0 .. v9}, Lh2/q6;->a(Lx2/s;JJFLk1/q1;Lt2/b;Ll2/o;I)V

    .line 29
    .line 30
    .line 31
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    return-object p0
.end method
