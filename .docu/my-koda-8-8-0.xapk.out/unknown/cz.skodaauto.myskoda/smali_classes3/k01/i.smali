.class public final synthetic Lk01/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:Lk01/p;

.field public final synthetic e:I

.field public final synthetic f:J


# direct methods
.method public synthetic constructor <init>(Lk01/p;IJ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk01/i;->d:Lk01/p;

    .line 5
    .line 6
    iput p2, p0, Lk01/i;->e:I

    .line 7
    .line 8
    iput-wide p3, p0, Lk01/i;->f:J

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lk01/i;->d:Lk01/p;

    .line 2
    .line 3
    iget v1, p0, Lk01/i;->e:I

    .line 4
    .line 5
    iget-wide v2, p0, Lk01/i;->f:J

    .line 6
    .line 7
    :try_start_0
    iget-object p0, v0, Lk01/p;->z:Lk01/y;

    .line 8
    .line 9
    invoke-virtual {p0, v1, v2, v3}, Lk01/y;->k(IJ)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 10
    .line 11
    .line 12
    goto :goto_0

    .line 13
    :catch_0
    move-exception p0

    .line 14
    sget-object v1, Lk01/b;->g:Lk01/b;

    .line 15
    .line 16
    invoke-virtual {v0, v1, v1, p0}, Lk01/p;->a(Lk01/b;Lk01/b;Ljava/io/IOException;)V

    .line 17
    .line 18
    .line 19
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 20
    .line 21
    return-object p0
.end method
