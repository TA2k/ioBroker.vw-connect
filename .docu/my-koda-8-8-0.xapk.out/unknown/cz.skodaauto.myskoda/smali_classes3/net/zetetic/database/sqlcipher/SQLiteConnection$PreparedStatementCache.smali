.class final Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatementCache;
.super Landroid/util/LruCache;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lnet/zetetic/database/sqlcipher/SQLiteConnection;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x11
    name = "PreparedStatementCache"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Landroid/util/LruCache<",
        "Ljava/lang/String;",
        "Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;",
        ">;"
    }
.end annotation


# instance fields
.field final synthetic this$0:Lnet/zetetic/database/sqlcipher/SQLiteConnection;


# direct methods
.method public constructor <init>(Lnet/zetetic/database/sqlcipher/SQLiteConnection;I)V
    .locals 0

    .line 1
    iput-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatementCache;->this$0:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 2
    .line 3
    invoke-direct {p0, p2}, Landroid/util/LruCache;-><init>(I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public dump(Landroid/util/Printer;)V
    .locals 6

    .line 1
    const-string v0, "  Prepared statement cache:"

    .line 2
    .line 3
    invoke-interface {p1, v0}, Landroid/util/Printer;->println(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Landroid/util/LruCache;->snapshot()Ljava/util/Map;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-interface {p0}, Ljava/util/Map;->isEmpty()Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-nez v0, :cond_2

    .line 15
    .line 16
    invoke-interface {p0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    const/4 v0, 0x0

    .line 25
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-eqz v1, :cond_1

    .line 30
    .line 31
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    check-cast v1, Ljava/util/Map$Entry;

    .line 36
    .line 37
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v2

    .line 41
    check-cast v2, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;

    .line 42
    .line 43
    iget-boolean v3, v2, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mInCache:Z

    .line 44
    .line 45
    if-eqz v3, :cond_0

    .line 46
    .line 47
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    check-cast v1, Ljava/lang/String;

    .line 52
    .line 53
    const-string v3, "    "

    .line 54
    .line 55
    const-string v4, ": statementPtr=0x"

    .line 56
    .line 57
    invoke-static {v3, v0, v4}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    move-result-object v3

    .line 61
    iget-wide v4, v2, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mStatementPtr:J

    .line 62
    .line 63
    invoke-static {v4, v5}, Ljava/lang/Long;->toHexString(J)Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object v4

    .line 67
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    const-string v4, ", numParameters="

    .line 71
    .line 72
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    iget v4, v2, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mNumParameters:I

    .line 76
    .line 77
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    const-string v4, ", type="

    .line 81
    .line 82
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    iget v4, v2, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mType:I

    .line 86
    .line 87
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    const-string v4, ", readOnly="

    .line 91
    .line 92
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    iget-boolean v2, v2, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mReadOnly:Z

    .line 96
    .line 97
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    const-string v2, ", sql=\""

    .line 101
    .line 102
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    invoke-static {v1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object v1

    .line 109
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 110
    .line 111
    .line 112
    const-string v1, "\""

    .line 113
    .line 114
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 115
    .line 116
    .line 117
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object v1

    .line 121
    invoke-interface {p1, v1}, Landroid/util/Printer;->println(Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 125
    .line 126
    goto :goto_0

    .line 127
    :cond_1
    return-void

    .line 128
    :cond_2
    const-string p0, "    <none>"

    .line 129
    .line 130
    invoke-interface {p1, p0}, Landroid/util/Printer;->println(Ljava/lang/String;)V

    .line 131
    .line 132
    .line 133
    return-void
.end method

.method public bridge synthetic entryRemoved(ZLjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p2, Ljava/lang/String;

    check-cast p3, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;

    check-cast p4, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;

    invoke-virtual {p0, p1, p2, p3, p4}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatementCache;->entryRemoved(ZLjava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V

    return-void
.end method

.method public entryRemoved(ZLjava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V
    .locals 0

    const/4 p1, 0x0

    .line 2
    iput-boolean p1, p3, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mInCache:Z

    .line 3
    iget-boolean p1, p3, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mInUse:Z

    if-nez p1, :cond_0

    .line 4
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatementCache;->this$0:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    invoke-static {p0, p3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->a(Lnet/zetetic/database/sqlcipher/SQLiteConnection;Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V

    :cond_0
    return-void
.end method
