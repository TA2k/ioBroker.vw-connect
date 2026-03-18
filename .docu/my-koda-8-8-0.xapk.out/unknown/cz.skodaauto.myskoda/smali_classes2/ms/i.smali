.class public final Lms/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lh8/o;

.field public final b:Lms/h;


# direct methods
.method public constructor <init>(Lh8/o;Lss/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lms/i;->a:Lh8/o;

    .line 5
    .line 6
    new-instance p1, Lms/h;

    .line 7
    .line 8
    invoke-direct {p1, p2}, Lms/h;-><init>(Lss/b;)V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lms/i;->b:Lms/h;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;)V
    .locals 2

    .line 1
    iget-object p0, p0, Lms/i;->b:Lms/h;

    .line 2
    .line 3
    monitor-enter p0

    .line 4
    :try_start_0
    iget-object v0, p0, Lms/h;->b:Ljava/lang/String;

    .line 5
    .line 6
    invoke-static {v0, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    iget-object v0, p0, Lms/h;->a:Lss/b;

    .line 13
    .line 14
    iget-object v1, p0, Lms/h;->c:Ljava/lang/String;

    .line 15
    .line 16
    invoke-static {v0, p1, v1}, Lms/h;->a(Lss/b;Ljava/lang/String;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lms/h;->b:Ljava/lang/String;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :catchall_0
    move-exception p1

    .line 23
    goto :goto_1

    .line 24
    :cond_0
    :goto_0
    monitor-exit p0

    .line 25
    return-void

    .line 26
    :goto_1
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 27
    throw p1
.end method
