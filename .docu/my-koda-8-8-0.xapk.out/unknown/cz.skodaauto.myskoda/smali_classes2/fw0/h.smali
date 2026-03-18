.class public final Lfw0/h;
.super Lrw0/d;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public final b:Ljava/lang/Long;

.field public final c:Low0/e;

.field public final synthetic d:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lkw0/c;Low0/e;Ljava/lang/Object;)V
    .locals 2

    const/4 v0, 0x1

    iput v0, p0, Lfw0/h;->a:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p3, p0, Lfw0/h;->d:Ljava/lang/Object;

    .line 3
    iget-object p1, p1, Lkw0/c;->c:Low0/n;

    .line 4
    sget-object p3, Low0/q;->a:Ljava/util/List;

    const-string p3, "Content-Length"

    invoke-virtual {p1, p3}, Lap0/o;->z(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    if-eqz p1, :cond_0

    invoke-static {p1}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    move-result-wide v0

    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object p1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    iput-object p1, p0, Lfw0/h;->b:Ljava/lang/Long;

    if-nez p2, :cond_1

    .line 5
    sget-object p1, Low0/b;->a:Low0/e;

    .line 6
    sget-object p2, Low0/b;->b:Low0/e;

    .line 7
    :cond_1
    iput-object p2, p0, Lfw0/h;->c:Low0/e;

    return-void
.end method

.method public constructor <init>(Lyw0/e;Low0/e;Ljava/lang/Object;)V
    .locals 2

    const/4 v0, 0x0

    iput v0, p0, Lfw0/h;->a:I

    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    iput-object p3, p0, Lfw0/h;->d:Ljava/lang/Object;

    .line 10
    iget-object p1, p1, Lyw0/e;->d:Ljava/lang/Object;

    .line 11
    check-cast p1, Lkw0/c;

    .line 12
    iget-object p1, p1, Lkw0/c;->c:Low0/n;

    .line 13
    sget-object p3, Low0/q;->a:Ljava/util/List;

    const-string p3, "Content-Length"

    invoke-virtual {p1, p3}, Lap0/o;->z(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    if-eqz p1, :cond_0

    invoke-static {p1}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    move-result-wide v0

    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object p1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    iput-object p1, p0, Lfw0/h;->b:Ljava/lang/Long;

    if-nez p2, :cond_1

    .line 14
    sget-object p1, Low0/b;->a:Low0/e;

    .line 15
    sget-object p2, Low0/b;->b:Low0/e;

    .line 16
    :cond_1
    iput-object p2, p0, Lfw0/h;->c:Low0/e;

    return-void
.end method


# virtual methods
.method public final a()Ljava/lang/Long;
    .locals 1

    .line 1
    iget v0, p0, Lfw0/h;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lfw0/h;->b:Ljava/lang/Long;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    iget-object p0, p0, Lfw0/h;->b:Ljava/lang/Long;

    .line 10
    .line 11
    return-object p0

    .line 12
    nop

    .line 13
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final b()Low0/e;
    .locals 1

    .line 1
    iget v0, p0, Lfw0/h;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lfw0/h;->c:Low0/e;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    iget-object p0, p0, Lfw0/h;->c:Low0/e;

    .line 10
    .line 11
    return-object p0

    .line 12
    nop

    .line 13
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
