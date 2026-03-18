.class Lcom/salesforce/marketingcloud/registration/e$d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
.implements Lcom/salesforce/marketingcloud/registration/c;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/registration/e;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "d"
.end annotation


# static fields
.field private static final j:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private final a:Ljava/lang/Object;

.field private final b:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private final c:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private final d:Lcom/salesforce/marketingcloud/registration/e$f;

.field private final e:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private f:Ljava/lang/String;

.field private g:Ljava/lang/String;

.field private h:Z

.field private i:Z


# direct methods
.method static constructor <clinit>()V
    .locals 47

    .line 1
    const-string v45, "signedString"

    .line 2
    .line 3
    const-string v46, "quietPushEnabled"

    .line 4
    .line 5
    const-string v1, "addressId"

    .line 6
    .line 7
    const-string v2, "alias"

    .line 8
    .line 9
    const-string v3, "apId"

    .line 10
    .line 11
    const-string v4, "backgroundRefreshEnabled"

    .line 12
    .line 13
    const-string v5, "badge"

    .line 14
    .line 15
    const-string v6, "channel"

    .line 16
    .line 17
    const-string v7, "contactId"

    .line 18
    .line 19
    const-string v8, "contactKey"

    .line 20
    .line 21
    const-string v9, "createdBy"

    .line 22
    .line 23
    const-string v10, "createdDate"

    .line 24
    .line 25
    const-string v11, "customObjectKey"

    .line 26
    .line 27
    const-string v12, "device"

    .line 28
    .line 29
    const-string v13, "deviceId"

    .line 30
    .line 31
    const-string v14, "deviceType"

    .line 32
    .line 33
    const-string v15, "gcmSenderId"

    .line 34
    .line 35
    const-string v16, "hardwareId"

    .line 36
    .line 37
    const-string v17, "isHonorDst"

    .line 38
    .line 39
    const-string v18, "lastAppOpen"

    .line 40
    .line 41
    const-string v19, "lastMessageOpen"

    .line 42
    .line 43
    const-string v20, "lastSend"

    .line 44
    .line 45
    const-string v21, "locationEnabled"

    .line 46
    .line 47
    const-string v22, "messageOpenCount"

    .line 48
    .line 49
    const-string v23, "modifiedBy"

    .line 50
    .line 51
    const-string v24, "modifiedDate"

    .line 52
    .line 53
    const-string v25, "optInDate"

    .line 54
    .line 55
    const-string v26, "optInMethodId"

    .line 56
    .line 57
    const-string v27, "optInStatusId"

    .line 58
    .line 59
    const-string v28, "optOutDate"

    .line 60
    .line 61
    const-string v29, "optOutMethodId"

    .line 62
    .line 63
    const-string v30, "optOutStatusId"

    .line 64
    .line 65
    const-string v31, "platform"

    .line 66
    .line 67
    const-string v32, "platformVersion"

    .line 68
    .line 69
    const-string v33, "providerToken"

    .line 70
    .line 71
    const-string v34, "proximityEnabled"

    .line 72
    .line 73
    const-string v35, "pushAddressExtensionId"

    .line 74
    .line 75
    const-string v36, "pushApplicationId"

    .line 76
    .line 77
    const-string v37, "sdkVersion"

    .line 78
    .line 79
    const-string v38, "sendCount"

    .line 80
    .line 81
    const-string v39, "source"

    .line 82
    .line 83
    const-string v40, "sourceObjectId"

    .line 84
    .line 85
    const-string v41, "status"

    .line 86
    .line 87
    const-string v42, "systemToken"

    .line 88
    .line 89
    const-string v43, "timezone"

    .line 90
    .line 91
    const-string v44, "utcOffset"

    .line 92
    .line 93
    filled-new-array/range {v1 .. v46}, [Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    new-instance v1, Ljava/util/ArrayList;

    .line 98
    .line 99
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 100
    .line 101
    .line 102
    const/4 v2, 0x0

    .line 103
    :goto_0
    const/16 v3, 0x2e

    .line 104
    .line 105
    if-ge v2, v3, :cond_0

    .line 106
    .line 107
    aget-object v3, v0, v2

    .line 108
    .line 109
    sget-object v4, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    .line 110
    .line 111
    invoke-virtual {v3, v4}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object v3

    .line 115
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    add-int/lit8 v2, v2, 0x1

    .line 119
    .line 120
    goto :goto_0

    .line 121
    :cond_0
    invoke-static {v1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 122
    .line 123
    .line 124
    move-result-object v0

    .line 125
    sput-object v0, Lcom/salesforce/marketingcloud/registration/e$d;->j:Ljava/util/List;

    .line 126
    .line 127
    return-void
.end method

.method public constructor <init>(Lcom/salesforce/marketingcloud/registration/e$f;Ljava/lang/String;Ljava/lang/String;Ljava/util/concurrent/ConcurrentHashMap;Ljava/util/concurrent/ConcurrentSkipListSet;Ljava/util/Set;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/registration/e$f;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/util/concurrent/ConcurrentHashMap<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;",
            "Ljava/util/concurrent/ConcurrentSkipListSet<",
            "Ljava/lang/String;",
            ">;",
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/lang/Object;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lcom/salesforce/marketingcloud/registration/e$d;->a:Ljava/lang/Object;

    .line 10
    .line 11
    new-instance v0, Ljava/util/TreeMap;

    .line 12
    .line 13
    sget-object v1, Ljava/lang/String;->CASE_INSENSITIVE_ORDER:Ljava/util/Comparator;

    .line 14
    .line 15
    invoke-direct {v0, v1}, Ljava/util/TreeMap;-><init>(Ljava/util/Comparator;)V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Lcom/salesforce/marketingcloud/registration/e$d;->b:Ljava/util/Map;

    .line 19
    .line 20
    new-instance v0, Ljava/util/TreeSet;

    .line 21
    .line 22
    invoke-direct {v0, v1}, Ljava/util/TreeSet;-><init>(Ljava/util/Comparator;)V

    .line 23
    .line 24
    .line 25
    iput-object v0, p0, Lcom/salesforce/marketingcloud/registration/e$d;->c:Ljava/util/Set;

    .line 26
    .line 27
    iput-object p1, p0, Lcom/salesforce/marketingcloud/registration/e$d;->d:Lcom/salesforce/marketingcloud/registration/e$f;

    .line 28
    .line 29
    iput-object p2, p0, Lcom/salesforce/marketingcloud/registration/e$d;->f:Ljava/lang/String;

    .line 30
    .line 31
    iput-object p3, p0, Lcom/salesforce/marketingcloud/registration/e$d;->g:Ljava/lang/String;

    .line 32
    .line 33
    new-instance p1, Lcom/salesforce/marketingcloud/registration/b;

    .line 34
    .line 35
    invoke-direct {p1, p4}, Lcom/salesforce/marketingcloud/registration/b;-><init>(Ljava/util/Map;)V

    .line 36
    .line 37
    .line 38
    iput-object p1, p0, Lcom/salesforce/marketingcloud/registration/e$d;->e:Ljava/util/Map;

    .line 39
    .line 40
    invoke-virtual {p5}, Ljava/util/concurrent/ConcurrentSkipListSet;->iterator()Ljava/util/Iterator;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 45
    .line 46
    .line 47
    move-result p2

    .line 48
    if-eqz p2, :cond_0

    .line 49
    .line 50
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object p2

    .line 54
    check-cast p2, Ljava/lang/String;

    .line 55
    .line 56
    iget-object p3, p0, Lcom/salesforce/marketingcloud/registration/e$d;->b:Ljava/util/Map;

    .line 57
    .line 58
    invoke-interface {p3, p2, p2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/e$d;->c:Ljava/util/Set;

    .line 63
    .line 64
    invoke-interface {p0, p6}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    .line 65
    .line 66
    .line 67
    return-void
.end method

.method private a(Ljava/lang/String;)Z
    .locals 2

    .line 19
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result p0

    const/4 v0, 0x0

    if-eqz p0, :cond_0

    .line 20
    sget-object p0, Lcom/salesforce/marketingcloud/registration/RegistrationManager;->a:Ljava/lang/String;

    new-array p1, v0, [Ljava/lang/Object;

    const-string v1, "The attribute you provided was null or empty."

    invoke-static {p0, v1, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return v0

    .line 21
    :cond_0
    invoke-virtual {p1}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object p0

    .line 22
    invoke-static {p0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result p1

    if-eqz p1, :cond_1

    .line 23
    sget-object p0, Lcom/salesforce/marketingcloud/registration/RegistrationManager;->a:Ljava/lang/String;

    new-array p1, v0, [Ljava/lang/Object;

    const-string v1, "The attribute you provided was blank."

    invoke-static {p0, v1, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return v0

    .line 24
    :cond_1
    sget-object p1, Lcom/salesforce/marketingcloud/registration/e$d;->j:Ljava/util/List;

    sget-object v1, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    invoke-virtual {p0, v1}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    move-result-object v1

    invoke-interface {p1, v1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_2

    .line 25
    sget-object p1, Lcom/salesforce/marketingcloud/registration/RegistrationManager;->a:Ljava/lang/String;

    filled-new-array {p0}, [Ljava/lang/Object;

    move-result-object p0

    const-string v1, "Attribute key \'%s\' is invalid and can not be added.  Please see documentation regarding Attributes and Reserved Words."

    invoke-static {p1, v1, p0}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return v0

    .line 26
    :cond_2
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result p1

    const/16 v1, 0x80

    if-le p1, v1, :cond_3

    .line 27
    sget-object p1, Lcom/salesforce/marketingcloud/registration/RegistrationManager;->a:Ljava/lang/String;

    .line 28
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result p0

    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p0

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    filled-new-array {p0, v1}, [Ljava/lang/Object;

    move-result-object p0

    .line 29
    const-string v1, "Your attribute key was %s characters long.  Attribute keys are restricted to %s characters.  Your attribute key will be truncated."

    invoke-static {p1, v1, p0}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return v0

    :cond_3
    const/4 p0, 0x1

    return p0
.end method

.method private b(Ljava/lang/String;)Z
    .locals 2

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    sget-object p0, Lcom/salesforce/marketingcloud/registration/RegistrationManager;->a:Ljava/lang/String;

    .line 4
    .line 5
    const/4 p1, 0x0

    .line 6
    new-array v0, p1, [Ljava/lang/Object;

    .line 7
    .line 8
    const-string v1, "Attribute value was null and will not be saved."

    .line 9
    .line 10
    invoke-static {p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    return p1

    .line 14
    :cond_0
    const/4 p0, 0x1

    .line 15
    return p0
.end method

.method private c(Ljava/lang/String;)Z
    .locals 0

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    invoke-static {p1}, Landroid/text/TextUtils;->getTrimmedLength(Ljava/lang/CharSequence;)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    if-lez p0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 p0, 0x0

    .line 11
    return p0

    .line 12
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 13
    return p0
.end method

.method private d(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/util/SFMCExtension;->getValidContactKey(Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    sget-object p1, Lcom/salesforce/marketingcloud/registration/RegistrationManager;->a:Ljava/lang/String;

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    new-array v0, v0, [Ljava/lang/Object;

    .line 11
    .line 12
    const-string v1, "An invalid ContactKey will not be transmitted to the Marketing Cloud and was NOT updated with the provided value."

    .line 13
    .line 14
    invoke-static {p1, v1, v0}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    :cond_0
    return-object p0
.end method

.method private e(Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0

    .line 8
    :cond_0
    return-object p1
.end method


# virtual methods
.method public a(Ljava/lang/String;Ljava/lang/String;Z)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/registration/e$d;->a:Ljava/lang/Object;

    monitor-enter v0

    .line 2
    :try_start_0
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/registration/e$d;->a(Ljava/lang/String;)Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-direct {p0, p2}, Lcom/salesforce/marketingcloud/registration/e$d;->b(Ljava/lang/String;)Z

    move-result v1

    if-eqz v1, :cond_0

    .line 3
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/e$d;->e:Ljava/util/Map;

    invoke-interface {v1, p1, p2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/4 p1, 0x1

    .line 4
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/registration/e$d;->h:Z

    .line 5
    iput-boolean p3, p0, Lcom/salesforce/marketingcloud/registration/e$d;->i:Z

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    .line 6
    :cond_0
    :goto_0
    monitor-exit v0

    return-object p0

    .line 7
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0
.end method

.method public a(Ljava/lang/String;Ljava/util/Map;Z)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;Z)",
            "Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;"
        }
    .end annotation

    .line 14
    invoke-virtual {p0, p1, p3}, Lcom/salesforce/marketingcloud/registration/e$d;->a(Ljava/lang/String;Z)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;

    .line 15
    invoke-interface {p2}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p2

    if-eqz p2, :cond_0

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/util/Map$Entry;

    .line 16
    invoke-interface {p2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    invoke-interface {p2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/lang/String;

    invoke-virtual {p0, v0, p2, p3}, Lcom/salesforce/marketingcloud/registration/e$d;->a(Ljava/lang/String;Ljava/lang/String;Z)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;

    goto :goto_0

    :cond_0
    return-object p0
.end method

.method public a(Ljava/lang/String;Z)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
    .locals 2

    .line 8
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/registration/e$d;->d(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    if-eqz p1, :cond_0

    .line 9
    iget-object v0, p0, Lcom/salesforce/marketingcloud/registration/e$d;->a:Ljava/lang/Object;

    monitor-enter v0

    const/4 v1, 0x1

    .line 10
    :try_start_0
    iput-boolean v1, p0, Lcom/salesforce/marketingcloud/registration/e$d;->h:Z

    .line 11
    iput-boolean p2, p0, Lcom/salesforce/marketingcloud/registration/e$d;->i:Z

    .line 12
    iput-object p1, p0, Lcom/salesforce/marketingcloud/registration/e$d;->g:Ljava/lang/String;

    .line 13
    monitor-exit v0

    return-object p0

    :catchall_0
    move-exception p0

    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0

    :cond_0
    return-object p0
.end method

.method public a(Ljava/util/Map;Z)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;Z)",
            "Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;"
        }
    .end annotation

    .line 17
    invoke-interface {p1}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/Map$Entry;

    .line 18
    invoke-interface {v0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    invoke-virtual {p0, v1, v0, p2}, Lcom/salesforce/marketingcloud/registration/e$d;->a(Ljava/lang/String;Ljava/lang/String;Z)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;

    goto :goto_0

    :cond_0
    return-object p0
.end method

.method public addTag(Ljava/lang/String;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
    .locals 2

    .line 1
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/registration/e$d;->e(Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iget-object v0, p0, Lcom/salesforce/marketingcloud/registration/e$d;->a:Ljava/lang/Object;

    .line 6
    .line 7
    monitor-enter v0

    .line 8
    :try_start_0
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    if-nez v1, :cond_0

    .line 13
    .line 14
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/e$d;->b:Ljava/util/Map;

    .line 15
    .line 16
    invoke-interface {v1, p1, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    invoke-virtual {p1, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result p1

    .line 24
    if-nez p1, :cond_0

    .line 25
    .line 26
    const/4 p1, 0x1

    .line 27
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/registration/e$d;->h:Z

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :catchall_0
    move-exception p0

    .line 31
    goto :goto_1

    .line 32
    :cond_0
    :goto_0
    monitor-exit v0

    .line 33
    return-object p0

    .line 34
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 35
    throw p0
.end method

.method public addTags(Ljava/lang/Iterable;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Iterable<",
            "Ljava/lang/String;",
            ">;)",
            "Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;"
        }
    .end annotation

    if-nez p1, :cond_0

    goto :goto_1

    .line 1
    :cond_0
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    .line 2
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/registration/e$d;->addTag(Ljava/lang/String;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;

    goto :goto_0

    :cond_1
    :goto_1
    return-object p0
.end method

.method public varargs addTags([Ljava/lang/String;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
    .locals 3

    if-eqz p1, :cond_1

    .line 3
    array-length v0, p1

    if-nez v0, :cond_0

    goto :goto_1

    .line 4
    :cond_0
    array-length v0, p1

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_1

    aget-object v2, p1, v1

    .line 5
    invoke-virtual {p0, v2}, Lcom/salesforce/marketingcloud/registration/e$d;->addTag(Ljava/lang/String;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_1
    :goto_1
    return-object p0
.end method

.method public clearAttribute(Ljava/lang/String;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
    .locals 1

    .line 1
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/registration/e$d;->a(Ljava/lang/String;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    const-string v0, ""

    .line 9
    .line 10
    invoke-virtual {p0, p1, v0}, Lcom/salesforce/marketingcloud/registration/e$d;->setAttribute(Ljava/lang/String;Ljava/lang/String;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public clearAttributes(Ljava/lang/Iterable;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Iterable<",
            "Ljava/lang/String;",
            ">;)",
            "Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;"
        }
    .end annotation

    .line 1
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    .line 2
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/registration/e$d;->clearAttribute(Ljava/lang/String;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;

    goto :goto_0

    :cond_0
    return-object p0
.end method

.method public varargs clearAttributes([Ljava/lang/String;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
    .locals 3

    if-eqz p1, :cond_1

    .line 3
    array-length v0, p1

    if-nez v0, :cond_0

    goto :goto_1

    .line 4
    :cond_0
    array-length v0, p1

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_1

    aget-object v2, p1, v1

    .line 5
    invoke-virtual {p0, v2}, Lcom/salesforce/marketingcloud/registration/e$d;->clearAttribute(Ljava/lang/String;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_1
    :goto_1
    return-object p0
.end method

.method public clearTags()Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/registration/e$d;->a:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/e$d;->b:Ljava/util/Map;

    .line 5
    .line 6
    invoke-interface {v1}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    iget-object v2, p0, Lcom/salesforce/marketingcloud/registration/e$d;->c:Ljava/util/Set;

    .line 11
    .line 12
    invoke-interface {v1, v2}, Ljava/util/Set;->retainAll(Ljava/util/Collection;)Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    const/4 v1, 0x1

    .line 19
    iput-boolean v1, p0, Lcom/salesforce/marketingcloud/registration/e$d;->h:Z

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
    return-object p0

    .line 26
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 27
    throw p0
.end method

.method public commit()Z
    .locals 8

    .line 1
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/e$d;->a:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v1

    .line 4
    :try_start_0
    iget-boolean v0, p0, Lcom/salesforce/marketingcloud/registration/e$d;->h:Z

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    iget-object v2, p0, Lcom/salesforce/marketingcloud/registration/e$d;->d:Lcom/salesforce/marketingcloud/registration/e$f;

    .line 9
    .line 10
    if-eqz v2, :cond_0

    .line 11
    .line 12
    iget-object v3, p0, Lcom/salesforce/marketingcloud/registration/e$d;->f:Ljava/lang/String;

    .line 13
    .line 14
    iget-object v4, p0, Lcom/salesforce/marketingcloud/registration/e$d;->g:Ljava/lang/String;

    .line 15
    .line 16
    iget-object v5, p0, Lcom/salesforce/marketingcloud/registration/e$d;->e:Ljava/util/Map;

    .line 17
    .line 18
    iget-object v0, p0, Lcom/salesforce/marketingcloud/registration/e$d;->b:Ljava/util/Map;

    .line 19
    .line 20
    invoke-interface {v0}, Ljava/util/Map;->values()Ljava/util/Collection;

    .line 21
    .line 22
    .line 23
    move-result-object v6

    .line 24
    iget-boolean v7, p0, Lcom/salesforce/marketingcloud/registration/e$d;->i:Z

    .line 25
    .line 26
    invoke-interface/range {v2 .. v7}, Lcom/salesforce/marketingcloud/registration/e$f;->a(Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/util/Collection;Z)V

    .line 27
    .line 28
    .line 29
    const/4 p0, 0x1

    .line 30
    monitor-exit v1

    .line 31
    return p0

    .line 32
    :catchall_0
    move-exception v0

    .line 33
    move-object p0, v0

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    monitor-exit v1

    .line 36
    const/4 p0, 0x0

    .line 37
    return p0

    .line 38
    :goto_0
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 39
    throw p0
.end method

.method public removeTag(Ljava/lang/String;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
    .locals 2

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    return-object p0

    .line 4
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/registration/e$d;->a:Ljava/lang/Object;

    .line 5
    .line 6
    monitor-enter v0

    .line 7
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/e$d;->c:Ljava/util/Set;

    .line 8
    .line 9
    invoke-interface {v1, p1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-nez v1, :cond_1

    .line 14
    .line 15
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/e$d;->b:Ljava/util/Map;

    .line 16
    .line 17
    invoke-interface {v1, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    if-eqz p1, :cond_1

    .line 22
    .line 23
    const/4 p1, 0x1

    .line 24
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/registration/e$d;->h:Z

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :catchall_0
    move-exception p0

    .line 28
    goto :goto_1

    .line 29
    :cond_1
    :goto_0
    monitor-exit v0

    .line 30
    return-object p0

    .line 31
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 32
    throw p0
.end method

.method public removeTags(Ljava/lang/Iterable;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Iterable<",
            "Ljava/lang/String;",
            ">;)",
            "Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;"
        }
    .end annotation

    if-nez p1, :cond_0

    goto :goto_1

    .line 1
    :cond_0
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    .line 2
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/registration/e$d;->removeTag(Ljava/lang/String;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;

    goto :goto_0

    :cond_1
    :goto_1
    return-object p0
.end method

.method public varargs removeTags([Ljava/lang/String;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
    .locals 3

    if-eqz p1, :cond_1

    .line 3
    array-length v0, p1

    if-nez v0, :cond_0

    goto :goto_1

    .line 4
    :cond_0
    array-length v0, p1

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_1

    aget-object v2, p1, v1

    .line 5
    invoke-virtual {p0, v2}, Lcom/salesforce/marketingcloud/registration/e$d;->removeTag(Ljava/lang/String;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_1
    :goto_1
    return-object p0
.end method

.method public setAttribute(Ljava/lang/String;Ljava/lang/String;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
    .locals 1
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-virtual {p0, p1, p2, v0}, Lcom/salesforce/marketingcloud/registration/e$d;->a(Ljava/lang/String;Ljava/lang/String;Z)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    return-object p0
.end method

.method public setContactKey(Ljava/lang/String;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
    .locals 1
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-virtual {p0, p1, v0}, Lcom/salesforce/marketingcloud/registration/e$d;->a(Ljava/lang/String;Z)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    return-object p0
.end method

.method public setSignedString(Ljava/lang/String;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/registration/e$d;->a:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/registration/e$d;->c(Ljava/lang/String;)Z

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    iput-object p1, p0, Lcom/salesforce/marketingcloud/registration/e$d;->f:Ljava/lang/String;

    .line 11
    .line 12
    const/4 p1, 0x1

    .line 13
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/registration/e$d;->h:Z

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :catchall_0
    move-exception p0

    .line 17
    goto :goto_1

    .line 18
    :cond_0
    :goto_0
    monitor-exit v0

    .line 19
    return-object p0

    .line 20
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    throw p0
.end method
