.class Lnet/zetetic/database/sqlcipher/SQLiteDatabase$3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lnet/zetetic/database/sqlcipher/SQLiteTransactionListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->beginTransactionWithListenerNonExclusive(Landroid/database/sqlite/SQLiteTransactionListener;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

.field final synthetic val$transactionListener:Landroid/database/sqlite/SQLiteTransactionListener;


# direct methods
.method public constructor <init>(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;Landroid/database/sqlite/SQLiteTransactionListener;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase$3;->this$0:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 2
    .line 3
    iput-object p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase$3;->val$transactionListener:Landroid/database/sqlite/SQLiteTransactionListener;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public onBegin()V
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase$3;->val$transactionListener:Landroid/database/sqlite/SQLiteTransactionListener;

    .line 2
    .line 3
    invoke-interface {p0}, Landroid/database/sqlite/SQLiteTransactionListener;->onBegin()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public onCommit()V
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase$3;->val$transactionListener:Landroid/database/sqlite/SQLiteTransactionListener;

    .line 2
    .line 3
    invoke-interface {p0}, Landroid/database/sqlite/SQLiteTransactionListener;->onCommit()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public onRollback()V
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase$3;->val$transactionListener:Landroid/database/sqlite/SQLiteTransactionListener;

    .line 2
    .line 3
    invoke-interface {p0}, Landroid/database/sqlite/SQLiteTransactionListener;->onRollback()V

    .line 4
    .line 5
    .line 6
    return-void
.end method
