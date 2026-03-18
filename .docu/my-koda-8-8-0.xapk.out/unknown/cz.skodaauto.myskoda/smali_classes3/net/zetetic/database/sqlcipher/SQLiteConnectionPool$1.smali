.class Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/CancellationSignal$OnCancelListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->waitForConnection(Ljava/lang/String;ILandroid/os/CancellationSignal;)Lnet/zetetic/database/sqlcipher/SQLiteConnection;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

.field final synthetic val$nonce:I

.field final synthetic val$waiter:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;


# direct methods
.method public constructor <init>(Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;I)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$1;->this$0:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

    .line 2
    .line 3
    iput-object p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$1;->val$waiter:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 4
    .line 5
    iput p3, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$1;->val$nonce:I

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public onCancel()V
    .locals 4

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$1;->this$0:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

    .line 2
    .line 3
    invoke-static {v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->a(Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    monitor-enter v0

    .line 8
    :try_start_0
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$1;->val$waiter:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 9
    .line 10
    iget v2, v1, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mNonce:I

    .line 11
    .line 12
    iget v3, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$1;->val$nonce:I

    .line 13
    .line 14
    if-ne v2, v3, :cond_0

    .line 15
    .line 16
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$1;->this$0:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

    .line 17
    .line 18
    invoke-static {p0, v1}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->b(Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;)V

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :catchall_0
    move-exception p0

    .line 23
    goto :goto_1

    .line 24
    :cond_0
    :goto_0
    monitor-exit v0

    .line 25
    return-void

    .line 26
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 27
    throw p0
.end method
