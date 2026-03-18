.class public final synthetic Le1/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Le3/p;

.field public final synthetic e:J

.field public final synthetic f:J

.field public final synthetic g:Lg3/e;


# direct methods
.method public synthetic constructor <init>(Le3/p0;JJLg3/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Le1/p;->d:Le3/p;

    .line 5
    .line 6
    iput-wide p2, p0, Le1/p;->e:J

    .line 7
    .line 8
    iput-wide p4, p0, Le1/p;->f:J

    .line 9
    .line 10
    iput-object p6, p0, Le1/p;->g:Lg3/e;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    move-object v0, p1

    .line 2
    check-cast v0, Lv3/j0;

    .line 3
    .line 4
    invoke-virtual {v0}, Lv3/j0;->b()V

    .line 5
    .line 6
    .line 7
    const/4 v8, 0x0

    .line 8
    const/16 v9, 0x68

    .line 9
    .line 10
    iget-object v1, p0, Le1/p;->d:Le3/p;

    .line 11
    .line 12
    iget-wide v2, p0, Le1/p;->e:J

    .line 13
    .line 14
    iget-wide v4, p0, Le1/p;->f:J

    .line 15
    .line 16
    const/4 v6, 0x0

    .line 17
    iget-object v7, p0, Le1/p;->g:Lg3/e;

    .line 18
    .line 19
    invoke-static/range {v0 .. v9}, Lg3/d;->i0(Lg3/d;Le3/p;JJFLg3/e;II)V

    .line 20
    .line 21
    .line 22
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    return-object p0
.end method
