.class public final synthetic Lh2/va;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:J

.field public final synthetic f:J

.field public final synthetic g:Z

.field public final synthetic h:Lt2/b;

.field public final synthetic i:I


# direct methods
.method public synthetic constructor <init>(JJZLt2/b;II)V
    .locals 0

    .line 1
    iput p8, p0, Lh2/va;->d:I

    .line 2
    .line 3
    iput-wide p1, p0, Lh2/va;->e:J

    .line 4
    .line 5
    iput-wide p3, p0, Lh2/va;->f:J

    .line 6
    .line 7
    iput-boolean p5, p0, Lh2/va;->g:Z

    .line 8
    .line 9
    iput-object p6, p0, Lh2/va;->h:Lt2/b;

    .line 10
    .line 11
    iput p7, p0, Lh2/va;->i:I

    .line 12
    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lh2/va;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v7, p1

    .line 7
    check-cast v7, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    iget p1, p0, Lh2/va;->i:I

    .line 15
    .line 16
    or-int/lit8 p1, p1, 0x1

    .line 17
    .line 18
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 19
    .line 20
    .line 21
    move-result v8

    .line 22
    iget-wide v1, p0, Lh2/va;->e:J

    .line 23
    .line 24
    iget-wide v3, p0, Lh2/va;->f:J

    .line 25
    .line 26
    iget-boolean v5, p0, Lh2/va;->g:Z

    .line 27
    .line 28
    iget-object v6, p0, Lh2/va;->h:Lt2/b;

    .line 29
    .line 30
    invoke-static/range {v1 .. v8}, Li91/j0;->n(JJZLt2/b;Ll2/o;I)V

    .line 31
    .line 32
    .line 33
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    return-object p0

    .line 36
    :pswitch_0
    move-object v6, p1

    .line 37
    check-cast v6, Ll2/o;

    .line 38
    .line 39
    check-cast p2, Ljava/lang/Integer;

    .line 40
    .line 41
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    iget p1, p0, Lh2/va;->i:I

    .line 45
    .line 46
    or-int/lit8 p1, p1, 0x1

    .line 47
    .line 48
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 49
    .line 50
    .line 51
    move-result v7

    .line 52
    iget-wide v0, p0, Lh2/va;->e:J

    .line 53
    .line 54
    iget-wide v2, p0, Lh2/va;->f:J

    .line 55
    .line 56
    iget-boolean v4, p0, Lh2/va;->g:Z

    .line 57
    .line 58
    iget-object v5, p0, Lh2/va;->h:Lt2/b;

    .line 59
    .line 60
    invoke-static/range {v0 .. v7}, Lh2/wa;->d(JJZLt2/b;Ll2/o;I)V

    .line 61
    .line 62
    .line 63
    goto :goto_0

    .line 64
    nop

    .line 65
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
