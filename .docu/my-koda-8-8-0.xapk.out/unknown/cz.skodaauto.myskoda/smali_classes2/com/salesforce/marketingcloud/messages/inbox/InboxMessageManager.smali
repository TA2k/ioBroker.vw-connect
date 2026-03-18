.class public interface abstract Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager$InboxRefreshListener;,
        Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager$InboxResponseListener;
    }
.end annotation


# static fields
.field public static final TAG:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "InboxMessageManager"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public abstract deleteMessage(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)V
.end method

.method public abstract deleteMessage(Ljava/lang/String;)V
.end method

.method public abstract disableInbox()V
.end method

.method public abstract enableInbox()V
.end method

.method public abstract getDeletedMessageCount()I
.end method

.method public abstract getDeletedMessages()Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;",
            ">;"
        }
    .end annotation
.end method

.method public abstract getMessageCount()I
.end method

.method public abstract getMessages()Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;",
            ">;"
        }
    .end annotation
.end method

.method public abstract getReadMessageCount()I
.end method

.method public abstract getReadMessages()Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;",
            ">;"
        }
    .end annotation
.end method

.method public abstract getUnreadMessageCount()I
.end method

.method public abstract getUnreadMessages()Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;",
            ">;"
        }
    .end annotation
.end method

.method public abstract isInboxEnabled()Z
.end method

.method public abstract markAllMessagesDeleted()V
.end method

.method public abstract markAllMessagesRead()V
.end method

.method public abstract refreshInbox(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager$InboxRefreshListener;)V
.end method

.method public abstract registerInboxResponseListener(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager$InboxResponseListener;)V
.end method

.method public abstract setMessageRead(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)V
.end method

.method public abstract setMessageRead(Ljava/lang/String;)V
.end method

.method public abstract unregisterInboxResponseListener(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager$InboxResponseListener;)V
.end method
